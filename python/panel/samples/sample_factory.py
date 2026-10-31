from __future__ import annotations

import base64
import codecs
import os
import random
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from faker import Faker
from jinja2 import Environment, FileSystemLoader

try:
    from ..build import build
    from . import eagle, sample_resources
except ImportError:
    # Run as a script (``python panel/samples/sample_factory.py``): put the
    # python/ directory on sys.path so the panel package is importable.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from panel.build import build
    from panel.samples import eagle, sample_resources

_POPEN = subprocess.Popen

LANGUAGES = ("c", "cpp")
CUSTOM_ID = "custom"
SAMPLE_KEEP = 12
SLEEP_MAX = 3600
NOISE_NET = "203.0.113."
KNOWN_DOMAINS = ("www.microsoft.com", "docs.python.org", "www.gnu.org")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_UINT32 = 0xFFFFFFFF
_NAME_RNG = random.Random()
_SOURCE_ENV = Environment(
    loader=FileSystemLoader(str(Path(__file__).resolve().parent)),
    autoescape=False,
    keep_trailing_newline=True,
)


def _token(length: int = 6) -> str:
    return f"{_NAME_RNG.getrandbits(32):08x}"[:length]

ENCODINGS = {
    "mixed": "Draws an encoded shape per value: ROT13, XOR, Base64 or chained.",
    "plain": "Stores the value exactly as drawn.",
    "rot13": "ROT13 over letters - honoured as chosen, even for all-digit IPs.",
    "xor": "A one-byte XOR key stated in the source, undone at runtime.",
    "base64": "Base64 text, decoded at runtime before it is printed.",
    "chained": "ROT13 -> Base64 -> XOR, unwound in reverse at runtime.",
}

FEATURES = (
    "strings",
    "wide",
    "imports",
    "sus",
    "noise",
    "iocs",
    "math",
    "random",
    "loop",
    "buffer_overflow",
    "double_free",
    "uaf",
    "stack_crash",
    "integer_overflow",
    "socket",
)

_FEATURE_NOTES = {
    "strings": "Three Faker strings declared as char* and printed with puts() - string-extraction bait.",
    "wide": "A UTF-16 (wchar_t) literal printed with %ls - width bait for the string pass.",
    "imports": "LoadLibraryA(kernel32) plus GetProcAddress(\"Sleep\") - the lookup runs, the API does not.",
    "sus": "Use suspicious functions: read-only calls are made, heavyweight names stay inert data.",
    "noise": "A TEST-NET-3 IP and a known benign domain (RFC 5737 - never dialled).",
    "iocs": "An IP and a domain drawn from the Generator resources pools, stored in the chosen encoding.",
    "math": "Two integer/float arithmetic blocks with their own operands and result printf.",
    "random": "srand(time(NULL)) plus a rand()%%N value, so two builds differ at runtime.",
    "loop": "A counted for-loop whose body prints and breaks at a random iteration.",
    "buffer_overflow": "malloc(8) then strcpy of a longer string - a stated heap overflow.",
    "double_free": "One allocation freed twice - a stated invalid free.",
    "uaf": "A pointer printed, freed, then printed again - a stated use-after-free.",
    "stack_crash": "An 8 MiB local array memset in place - a stated stack exhaustion.",
    "integer_overflow": "INT_MAX incremented once - a stated signed-overflow wrap.",
    "socket": "WSAStartup + connect to 127.0.0.1 only - loopback bait, nothing external is dialled.",
}

_TEMPLATES = [
    {"id": "c_minimal", "language": "c", "features": [],
     "label": "Empty main", "description": "An int main with nothing in it - the nothing-baseline."},
    {"id": "c_strings", "language": "c", "features": ["strings", "wide"],
     "label": "String talker", "description": "Faker strings and a wide literal, printed."},
    {"id": "c_imports", "language": "c", "features": ["imports", "sus"],
     "label": "Import talker", "description": "Kernel32 looked up, debugger flag read, nothing executed."},
    {"id": "c_math", "language": "c", "features": ["math", "random"],
     "label": "Math and randomness", "description": "Arithmetic blocks plus a seeded rand() value."},
    {"id": "c_loops", "language": "c", "features": ["loop", "math"],
     "label": "Loop and arithmetic", "description": "A counted loop with a break and math inside it."},
    {"id": "c_noise", "language": "c", "features": ["noise"],
     "label": "Noise only", "description": "The TEST-NET-3 IP and benign domain pair alone."},
    {"id": "c_vulns", "language": "c", "features": [
        "buffer_overflow", "double_free", "uaf", "stack_crash",
        "integer_overflow"],
     "label": "Memory faults", "description": "Stated heap overflow, double free, use-after-free, stack exhaustion and integer wrap."},
    {"id": "c_socket", "language": "c", "features": ["socket"],
     "label": "Loopback socket", "description": "Winsock connect to 127.0.0.1 - captured, never external."},
    {"id": "cpp_minimal", "language": "cpp", "features": [],
     "label": "Empty main", "description": "An int main with nothing in it - the nothing-baseline."},
    {"id": "cpp_strings", "language": "cpp", "features": ["strings", "wide"],
     "label": "String talker", "description": "Faker strings and a wide literal, printed."},
    {"id": "cpp_imports", "language": "cpp", "features": ["imports", "sus"],
     "label": "Import talker", "description": "Kernel32 looked up, debugger flag read, nothing executed."},
    {"id": "cpp_math", "language": "cpp", "features": ["math", "random"],
     "label": "Math and randomness", "description": "Arithmetic blocks plus a seeded rand() value."},
    {"id": "cpp_loops", "language": "cpp", "features": ["loop", "math"],
     "label": "Loop and arithmetic", "description": "A counted loop with a break and math inside it."},
    {"id": "cpp_noise", "language": "cpp", "features": ["noise"],
     "label": "Noise only", "description": "The TEST-NET-3 IP and benign domain pair alone."},
    {"id": "cpp_vulns", "language": "cpp", "features": [
        "buffer_overflow", "double_free", "uaf", "stack_crash",
        "integer_overflow"],
     "label": "Memory faults", "description": "Stated heap overflow, double free, use-after-free, stack exhaustion and integer wrap."},
    {"id": "cpp_socket", "language": "cpp", "features": ["socket"],
     "label": "Loopback socket", "description": "Winsock connect to 127.0.0.1 - captured, never external."},
]

_HELPERS = {
    "rot13": (
        "static void sf_rot13(char *s) {\n"
        "    for (; *s; ++s) {\n"
        "        if (*s >= 'a' && *s <= 'z') *s = (char)('a' + (*s - 'a' + 13) % 26);\n"
        "        else if (*s >= 'A' && *s <= 'Z') *s = (char)('A' + (*s - 'A' + 13) % 26);\n"
        "    }\n"
        "}\n"
    ),
    "b64": (
        "static int sf_b64(const char *in, char *out, int cap) {\n"
        "    int val = 0, bits = 0, n = 0;\n"
        "    const char *p = in;\n"
        "    for (; *p && n < cap - 1; ++p) {\n"
        "        unsigned d;\n"
        "        char c = *p;\n"
        "        if (c >= 'A' && c <= 'Z') d = (unsigned)(c - 'A');\n"
        "        else if (c >= 'a' && c <= 'z') d = (unsigned)(c - 'a' + 26);\n"
        "        else if (c >= '0' && c <= '9') d = (unsigned)(c - '0' + 52);\n"
        "        else if (c == '+') d = 62u;\n"
        "        else if (c == '/') d = 63u;\n"
        "        else continue;\n"
        "        val = (val << 6) | (unsigned)d;\n"
        "        bits += 6;\n"
        "        if (bits >= 8) {\n"
        "            bits -= 8;\n"
        "            out[n++] = (char)((val >> bits) & 0xFF);\n"
        "        }\n"
        "    }\n"
        "    out[n] = 0;\n"
        "    return n;\n"
        "}\n"
    ),
}


class Function:
    def __init__(self, fn_type, function_name, n_instructions, n_variables,
                 code_block, function_args=None):
        self.fn_type = fn_type
        self.function_name = function_name
        self.n_instructions = n_instructions
        self.list_of_instructions = []
        self.n_variables = n_variables
        self.list_of_vars = []
        self.code_block = code_block
        self.function_args = function_args

    def return_function_object(self) -> dict:
        return {
            "function_type": self.fn_type,
            "function_name": self.function_name,
            "n_instructions": self.n_instructions,
            "list_of_instructions": self.list_of_instructions,
            "available_variables": self.n_variables,
            "function_code_block": self.code_block,
            "function_args": self.function_args,
        }


class Variable:
    def __init__(self):
        self.type = ""
        self.var_name = ""
        self.value = ""
        self.full_declaration = ""

    def return_variable_object(self) -> dict:
        return {
            "type": self.type,
            "var_name": self.var_name,
            "value": self.value,
            "full_dec": self.full_declaration,
        }


class CodeFactory:
    def __init__(self, type_src):
        if not type_src:
            raise TypeError("Type of Source code is None")
        if not isinstance(type_src, str):
            raise TypeError("Source Code Type needs to be a string")
        if type_src.lower() not in self.__return_available_src():
            raise TypeError("Only C and C++ are supported")
        self.Fake = Faker()
        Faker.seed(random.random())
        self.type_src = type_src
        self.__produced_vars = []

    def test_compile_file(self, optimize=False, source_file=None) -> bool:
        if not source_file:
            return False
        path = Path(source_file).resolve()
        if not path.exists() or os.path.getsize(str(path)) == 0:
            return False
        gcc_path = shutil.which("gcc")
        if not gcc_path:
            return False
        command = [gcc_path, source_file, "-o", f"{path.stem}_output.exe"]
        if optimize:
            command.insert(1, "-O2")
        proc = _POPEN(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = proc.communicate(timeout=120)
        return proc.returncode == 0

    def generate_safe_mem_allocated_string_block(self) -> Variable:
        Vi = Variable()
        var_type = "char*"
        Vi.type = var_type
        random_string_value = self.generateString()
        string_len = len(random_string_value)
        var_name = f"var_{self.generate_smaple_name()}"
        declaration = (
            "{} {} = NULL;\n"
            "{} = (char*) malloc({});\n"
            "memset({},0,{});\n"
            "memcpy({},{},{});\n"
            "printf(\"pointer value : %s\\n\",{});\n"
            "free({});\n"
            "{} = NULL;\n"
        ).format(var_type, var_name, var_name, string_len + 1, var_name, string_len,
                 var_name, '"{}"'.format(random_string_value.replace('"', '\\"')),
                 string_len + 1, var_name, var_name, var_name)
        Vi.var_name = var_name
        Vi.full_declaration = declaration
        Vi.value = random_string_value
        self.__produced_vars.append(Vi)
        return Vi

    def generate_xor_otp(self, string) -> str:
        gen_string = self.generateString()
        return gen_string[0:len(string)]

    def create_rot13_encoded_variables(self, string=None) -> str:
        if not string:
            string = self.generateString()
        return codecs.encode(string, "rot_13")

    def create_base64_encoded_variables(self, string=None) -> str:
        if not string:
            string = self.generateString()
        return base64.b64encode(string.encode()).decode("ascii")

    def generate_sleep_calls(self, sleep_amount=1) -> str:
        if not sleep_amount:
            sleep_amount = 1
        if sleep_amount < 0:
            sleep_amount = -sleep_amount
        if isinstance(sleep_amount, float):
            sleep_amount = int(sleep_amount)
        return f"Sleep({sleep_amount * 1000});"

    def create_xor_encoded_variables(self, string=None) -> str:
        if not string:
            string = self.generateString()
        key = self.generate_xor_otp(string)
        encoded = []
        for index, char in enumerate(string):
            encoded.append(ord(char) ^ ord(key[index % len(key)]))
        return "".join(chr(value) for value in encoded)

    def define_main(self, function_calls) -> str:
        if not function_calls:
            return ""
        return f"int main(void) {{\n    {function_calls};\n    return 0;\n}}\n"

    def generate_for_loop(self, import_list, instructions, loop_step, count_to,
                          break_of_instruction) -> str:
        if not import_list:
            return ""
        if not count_to:
            count_to = 1
        if not loop_step:
            loop_step = 1
        if not instructions:
            instructions = ['printf("loop body\\n");']
        counter_name = f"i_{self.generate_smaple_name()}"
        block = f"for (int {counter_name} = 0; {counter_name} < {count_to}; {counter_name} += {loop_step}) {{\n"
        counter = 0
        breaking = bool(break_of_instruction)
        limit = max(0, min(break_of_instruction - 1 if break_of_instruction else -1,
                           len(instructions) - 1))
        for instruction in instructions:
            block += f"    {instruction}\n"
            if breaking and counter == limit:
                block += f"    if ({counter_name} >= {counter}) break;\n"
            counter += 1
        block += "}\n"
        return block

    def generate_socket_block(self, port=9, ip="127.0.0.1", timeout_ms=500) -> str:
        block = (
            "#ifdef _WIN32\n"
            "    {\n"
            "        WSADATA wsa_data;\n"
            "        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0) {\n"
            "            SOCKET sock_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);\n"
            "            if (sock_handle != INVALID_SOCKET) {\n"
            "                DWORD timeout_value = (DWORD)@@TIMEOUT@@;\n"
            "                struct sockaddr_in addr;\n"
            "                setsockopt(sock_handle, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_value, sizeof(timeout_value));\n"
            "                addr.sin_family = AF_INET;\n"
            "                addr.sin_port = htons((u_short)@@PORT@@);\n"
            "                addr.sin_addr.s_addr = inet_addr(\"@@IP@@\");\n"
            "                connect(sock_handle, (struct sockaddr *)&addr, sizeof(addr));\n"
            "                closesocket(sock_handle);\n"
            "            }\n"
            "            WSACleanup();\n"
            "        }\n"
            "    }\n"
            "#endif\n"
        )
        return (block.replace("@@TIMEOUT@@", str(int(timeout_ms)))
                     .replace("@@PORT@@", str(int(port)))
                     .replace("@@IP@@", ip))

    def create_math_ops_c(self, n_math_ops: int) -> list:
        if not n_math_ops:
            n_math_ops = 1
        list_math_ops = []
        for _ in range(n_math_ops):
            math_op = random.choice(["+", "-", "*", "/"])
            results_var = Variable()
            type_var = "int" if random.randint(1, 3) == 1 else "float"
            if type_var == "int":
                v1 = self.create_int_variable()
                v2 = self.create_int_variable()
            else:
                v1 = self.create_float_variable()
                v2 = self.create_float_variable()
            results_var.type = type_var
            results_var.var_name = f"var_{self.generate_smaple_name()}"
            if math_op == "/" and not v2.value:
                math_op = "+"
            results_var.value = eval(f"{v1.value} {math_op} {v2.value}")
            results_var.full_declaration = (
                f"{v1.full_declaration}{v2.full_declaration}"
                f"{results_var.type} {results_var.var_name} = "
                f"{v1.var_name} {math_op} {v2.var_name};\n"
            )
            list_math_ops.append(results_var)
        return list_math_ops

    def generate_printf_instructions(self, variable: Variable) -> str:
        if not variable:
            return ""
        if variable.type == "int":
            spec = "%d"
        elif variable.type == "float":
            spec = "%0.2f"
        elif variable.type == "char*":
            spec = "%s"
        else:
            spec = "%p"
        return ('printf("Variable value : {} at address : %p\\n",{},&{});\n'
                .format(spec, variable.var_name, variable.var_name))

    def generateString(self):
        rand = random.randint(1, 4)
        if rand == 1:
            return self.Fake.ascii_company_email()
        if rand == 2:
            return self.Fake.mac_address()
        if rand == 3:
            return self.Fake.file_name()
        return self.Fake.color_name()

    def create_random_vars(self, nvars=4) -> list:
        rands = []
        for _ in range(nvars + 1):
            rand = random.randint(1, 3)
            if rand == 1:
                rands.append(self.create_int_variable())
            elif rand == 2:
                rands.append(self.create_float_variable())
            else:
                rands.append(self.create_char_variable(self.generateString()))
        return rands

    def return_list_of_variable(self):
        return self.__produced_vars

    def create_int_variable(self, value=0) -> Variable:
        Vi = Variable()
        variable = f"var_{self.generate_smaple_name()}"
        Vi.type = "int"
        Vi.var_name = variable
        variable_value = value if value else random.randint(0, random.randint(1000, 100000))
        Vi.value = variable_value
        self.__produced_vars.append(Vi)
        Vi.full_declaration = f"int {variable} = {variable_value};\n"
        return Vi

    def create_float_variable(self, value=0) -> Variable:
        Vi = Variable()
        variable = f"var_{self.generate_smaple_name()}"
        Vi.type = "float"
        Vi.var_name = variable
        variable_value = (value if value
                          else round(random.uniform(0.0, float(random.randint(1000, 100000))), 7))
        Vi.value = variable_value
        self.__produced_vars.append(Vi)
        Vi.full_declaration = f"float {variable} = {variable_value}f;\n"
        return Vi

    def create_char_variable(self, value="EMPTY") -> Variable:
        Vi = Variable()
        Vi.type = "char*"
        Vi.var_name = f"var_{_token(4)}"
        Vi.value = value
        Vi.full_declaration = ('{} {} = "{}";\n'
                               .format(Vi.type, Vi.var_name,
                                       str(value).replace('"', '\\"')))
        self.__produced_vars.append(Vi)
        return Vi

    def create_malloc_pointer(self, fixed_size: int) -> Variable:
        size = fixed_size if fixed_size else random.randint(1, 100000)
        v1 = Variable()
        v1.type = "char*"
        v1.var_name = f"var_{self.generate_smaple_name()}"
        v1.value = f"(char*) malloc({size})"
        v1.full_declaration = f"{v1.type} {v1.var_name} = {v1.value};\n"
        return v1

    def free_malloc_pointer(self, variable):
        if not variable or variable.type != "char*":
            return None
        free_line = f"free({variable.var_name});\n"
        if free_line not in variable.full_declaration:
            variable.full_declaration += free_line
        return variable

    def create_comment(self, comment):
        return f"/* {comment} */\n"

    def create_buffer_overflow_issues(self, fixed_size: int = 8) -> Variable:
        random_string = self.generateString() + "-overflow-padding"
        malloc_variable = self.create_malloc_pointer(fixed_size)
        va = Variable()
        va.type = "char*"
        va.var_name = f"var_{self.generate_smaple_name()}"
        va.value = '"{}"'.format(random_string.replace('"', '\\"'))
        va.full_declaration = (
            f"{malloc_variable.full_declaration}"
            f"char {va.var_name}[] = {va.value};\n"
            f"strcpy({malloc_variable.var_name}, {va.var_name});\n"
            f"printf(\"overflow %s\\n\", {malloc_variable.var_name});\n"
            f"{self.create_comment('buffer overflow by design')}"
        )
        return va

    def create_double_free_issues(self, n_frees=2, fixed_size: int = 16) -> Variable:
        n_frees = max(2, n_frees)
        var = self.create_malloc_pointer(fixed_size)
        var.full_declaration += self.create_comment("double free by design")
        for _ in range(n_frees):
            var.full_declaration += f"free({var.var_name});\n"
        return var

    def create_stack_crash(self) -> Variable:
        variable = Variable()
        variable.type = "char"
        variable.var_name = f"var_{self.generate_smaple_name()}"
        variable.full_declaration = (
            f"char {variable.var_name}[8 * 1024 * 1024];\n"
            f"memset({variable.var_name}, 0, sizeof({variable.var_name}));\n"
            f"printf(\"stack %d\\n\", (int){variable.var_name}[0]);\n"
            f"{self.create_comment('stack exhaustion by design')}"
        )
        return variable

    def create_integer_overflow_variable(self) -> Variable:
        v1 = self.create_int_variable(2147483647)
        v1.full_declaration += f"{v1.var_name} = {v1.var_name} + 1;\n"
        v1.full_declaration += self.create_comment("signed integer overflow by design")
        return v1

    def generate_free_after_use_vuln(self, fixed_size: int = 32) -> Variable:
        variable = self.create_malloc_pointer(fixed_size)
        variable.full_declaration = (
            f"{variable.full_declaration}"
            f"memset({variable.var_name}, 'A', {max(1, fixed_size - 1)});\n"
            f"printf(\"before free %p\\n\", (void *){variable.var_name});\n"
            f"free({variable.var_name});\n"
            f"printf(\"after free %s\\n\", {variable.var_name});\n"
            f"{self.create_comment('use after free by design')}"
        )
        return variable

    def overlay_pe_with_content(self, executable, file) -> bool:
        if not executable:
            return False
        exec_path = Path(executable).resolve()
        if not exec_path.is_file():
            return False
        if file and Path(file).is_file():
            content = Path(file).read_bytes()
        else:
            content = "".join(self.generateString() for _ in range(4)).encode()
        data = exec_path.read_bytes()
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False
        pe = int.from_bytes(data[0x3C:0x40], "little")
        if data[pe:pe + 4] != b"PE\0\0":
            return False
        coff = pe + 4
        sections = int.from_bytes(data[coff + 2:coff + 4], "little")
        opt_size = int.from_bytes(data[coff + 16:coff + 18], "little")
        table = coff + 20 + opt_size
        end = 0
        for index in range(sections):
            entry = table + index * 40
            raw_size = int.from_bytes(data[entry + 16:entry + 20], "little")
            raw_ptr = int.from_bytes(data[entry + 20:entry + 24], "little")
            end = max(end, raw_ptr + raw_size)
        with exec_path.open("ab") as handle:
            handle.write(b"\0" * max(0, end - len(data)))
            handle.write(content)
        return True

    def inject_random_logique(self, imports_list, seed_generator_only=True,
                              include_new_variable=True):
        if not imports_list:
            return ""
        if "#include <time.h>\n" not in imports_list:
            return ""
        srand_block = "srand(time(NULL));\n"
        if seed_generator_only:
            return srand_block
        if include_new_variable:
            v1 = Variable()
            v1.type = "int"
            v1.var_name = f"random_value_{self.generate_smaple_name()}"
            v1.value = random.randint(1, 100000)
            v1.full_declaration = (f"{srand_block}int {v1.var_name} = rand() % {v1.value};\n")
            return v1
        return ""

    def create_noise(self, noise_directory) -> list:
        noise_directory = Path(noise_directory).resolve()
        if not noise_directory.is_dir():
            return []
        list_of_iocs = []
        for entry in sorted(noise_directory.iterdir()):
            if not entry.is_file():
                continue
            try:
                lines = entry.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            if not lines:
                continue
            for _ in range(3):
                list_of_iocs.append(self.create_char_variable(random.choice(lines).strip()))
        return list_of_iocs

    def generate_function_name(self) -> str:
        return f"func_{_token(5)}"

    def __return_available_src(self):
        return ["c", "c++", "cpp"]

    def __return_available_imports(self):
        if self.type_src in ("c", "cpp"):
            return ["stdlib", "stdio", "unistd", "math", "windows"]
        return []

    def gen_instruction(self, linked_instruction=None, independent_instructions=None,
                        number_of_instruction=1) -> list:
        if not number_of_instruction or number_of_instruction < 1:
            number_of_instruction = 1
        pool = list(independent_instructions or [])
        generated = []
        for _ in range(number_of_instruction):
            if pool:
                generated.append(random.choice(pool))
            else:
                generated.append(self.generate_printf_instructions(self.create_int_variable()))
        return generated

    def generate_imports(self) -> list:
        return [f"#include <{name}.h>\n" for name in self.__return_available_imports()]

    def generate_functions(self, fn_type="int", stub_function=False, nfunctions=2,
                           n_variables=4, inst_count=10, instructions=None,
                           variables=None) -> Function:
        if fn_type not in ("void", "int", "float", "char*"):
            return None
        nfunctions = max(1, nfunctions)
        inst_count = max(1, inst_count)
        n_variables = max(1, n_variables)
        if instructions is None:
            instructions = self.gen_instruction(None, None, inst_count)
        else:
            instructions = list(instructions)
        block = "".join(instructions)
        name = self.generate_function_name()
        function = Function(fn_type, name, len(instructions), n_variables, block)
        function.list_of_instructions = list(instructions)
        function.list_of_vars = (list(variables) if variables is not None
                                 else self.create_random_vars(n_variables))
        if stub_function:
            function.code_block = ""
        return function

    def generate_smaple_name(self) -> str:
        return _token(6)

    def basic_layout(self, sample_name, add_print_statement=False,
                     add_sleep_times=False, add_functions=True) -> str:
        source = _compose_source(self.type_src, [], "mixed", 0, random.getrandbits(32))
        if not sample_name:
            sample_name = f"sample-{self.generate_smaple_name()}"
        Path(f"{sample_name}_source.c").write_text(source, encoding="utf-8")
        return source


def _allowed_features(language: str) -> list:
    if language not in LANGUAGES:
        return []
    return list(FEATURES)


def _template(language: str, template_id: str):
    for template in _TEMPLATES:
        if template["id"] == template_id and template["language"] == language:
            return template
    return None


def _templates() -> list:
    return [dict(t) for t in _TEMPLATES]


def _sleep_value(value) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, min(SLEEP_MAX, value))


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _rot13(value: str) -> str:
    return codecs.encode(value, "rot_13")


def _encoded_ioc(kind: str, value: str, mode: str, rng: random.Random,
                 helpers: set) -> list:
    var = f"resource_ioc_{kind}"
    size = max(len(value) * 2 + 8, 64)
    if mode == "plain":
        return [f'char {var}[] = "{_escape(value)}";\n',
                f'printf("resource ioc: %s\\n", {var});\n']
    if mode == "rot13":
        helpers.add("rot13")
        return [f'char {var}[] = "{_escape(_rot13(value))}";\n',
                f"sf_rot13({var});\n",
                f'printf("resource ioc: %s\\n", {var});\n']
    if mode == "base64":
        helpers.add("b64")
        encoded = base64.b64encode(value.encode()).decode("ascii")
        return ["{\n",
                f'const char enc[] = "{encoded}";\n',
                f"char {var}[{size}];\n",
                f"sf_b64(enc, {var}, sizeof({var}));\n",
                f'printf("resource ioc: %s\\n", {var});\n',
                "}\n"]
    key = rng.randint(1, 255)
    if mode == "xor":
        raw = [byte ^ key for byte in value.encode()]
        arr = ", ".join(f"0x{byte:02x}" for byte in raw)
        return ["{\n",
                f"const unsigned char enc[] = {{{arr}}};\n",
                f"char {var}[{size}];\n",
                "unsigned i;\n",
                f"for (i = 0; i < sizeof(enc); ++i) {var}[i] = (char)((enc[i] ^ 0x{key:02x}));\n",
                f"{var}[sizeof(enc)] = 0;\n",
                f'printf("resource ioc: %s\\n", {var});\n',
                "}\n"]
    helpers.add("b64")
    helpers.add("rot13")
    chained = base64.b64encode(_rot13(value).encode("ascii")).decode("ascii")
    raw = [ord(char) ^ key for char in chained]
    arr = "".join(f"\\x{byte:02x}" for byte in raw)
    return ["{\n",
            f"char {var}[{size}];\n",
            "/* chain stage 1/3: XOR the stored bytes */\n",
            f'const char enc[] = "{arr}";\n',
            "unsigned i;\n",
            # Sized from the literal, not a fixed 512: a long URL or registry
            # path would otherwise overrun the stage buffer before the decode.
            f"char stage[{len(chained) + 1}];\n",
            f"for (i = 0; i < sizeof(enc) - 1; ++i) stage[i] = (char)(enc[i] ^ 0x{key:02x});\n",
            "stage[sizeof(enc) - 1] = 0;\n",
            "/* chain stage 2/3: Base64 decode */\n",
            f"sf_b64(stage, {var}, sizeof({var}));\n",
            "/* chain stage 3/3: ROT13 */\n",
            f"sf_rot13({var});\n",
            f'printf("resource ioc: %s\\n", {var});\n',
            "}\n"]


def _ioc_uses(encoding: str, rng: random.Random) -> tuple[list, list, set]:
    mode = encoding
    instructions: list = []
    uses: list = []
    helpers: set = set()
    # Every pool, not a hardcoded pair: a kind added to sample_resources is
    # sampled here without touching this function again.
    for kind in sample_resources.KIND_ORDER:
        picked = sample_resources.pick(kind, rng)
        if not picked:
            continue
        if mode == "mixed":
            shape = rng.choice(("xor", "base64", "chained"))
        else:
            shape = mode
        instructions.extend(_encoded_ioc(kind, picked["value"], shape, rng, helpers))
        uses.append({
            "feature": "iocs",
            "kind": kind,
            "id": picked["id"],
            "label": picked["label"],
            "value": picked["value"],
            "encoding": shape,
        })
    return instructions, uses, helpers


def _compose_source(language: str, features: list, encoding: str,
                    sleep_seconds: int, seed: int, shape: dict):
    random.seed(seed)
    Faker.seed(seed)
    _NAME_RNG.seed(seed)
    rng = random.Random(seed)
    factory = CodeFactory(language)
    n_math = shape["n_math"]
    n_vars = shape["n_vars"]
    loop_count = shape["loop_count"]
    loop_step = shape["loop_step"]
    loop_break_at = shape["loop_break_at"]
    instruction_count = shape["instruction_count"]
    alloc_size = shape["alloc_size"]
    n_frees = shape["n_frees"]

    includes = ["#include <stdio.h>", "#include <stdlib.h>", "#include <string.h>"]
    if "wide" in features:
        includes.append("#include <wchar.h>")
    if "random" in features:
        includes.append("#include <time.h>")
    if "socket" in features:
        includes.extend(["#include <winsock2.h>", "#include <ws2tcpip.h>", "#include <windows.h>"])
    elif {"imports", "sus"} & set(features) or sleep_seconds:
        includes.append("#include <windows.h>")

    instructions = []
    helpers: set = set()
    noise = None
    resource_uses = []

    if "strings" in features:
        for _ in range(3):
            value = factory.create_char_variable(factory.generateString())
            instructions.append(value.full_declaration)
            instructions.append(f"puts({value.var_name});\n")

    if "wide" in features:
        wide_value = _escape(factory.generateString())
        wide_name = f"wide_value_{_token(4)}"
        instructions.append(f'wchar_t {wide_name}[] = L"{wide_value}";\n')
        instructions.append(f'printf("wide %ls\\n", {wide_name});\n')

    if "imports" in features:
        instructions.append(
            "#ifdef _WIN32\n"
            "    {\n"
            "        HMODULE k32 = LoadLibraryA(\"kernel32.dll\");\n"
            "        if (k32) {\n"
            "            FARPROC api = GetProcAddress(k32, \"Sleep\");\n"
            "            printf(\"kernel32 %p\\n\", (void *)api);\n"
            "            FreeLibrary(k32);\n"
            "        }\n"
            "    }\n"
            "#endif\n"
        )

    if "sus" in features:
        instructions.append(
            "#ifdef _WIN32\n"
            "    {\n"
            "        HANDLE heap = GetProcessHeap();\n"
            "        printf(\"tick %lu\\n\", (unsigned long)GetTickCount());\n"
            "        printf(\"debugger %d\\n\", IsDebuggerPresent());\n"
            "        printf(\"heap %p %llu\\n\", (void *)heap,\n"
            "               (unsigned long long)HeapSize(heap, 0, heap));\n"
            "        printf(\"names %s %s %s %s\\n\",\n"
            "               \"VirtualAlloc\", \"WriteProcessMemory\",\n"
            "               \"CreateRemoteThread\", \"SetWindowsHookEx\");\n"
            "    }\n"
            "#endif\n"
        )

    if "noise" in features:
        ip = f"{NOISE_NET}{rng.randint(1, 254)}"
        domain = rng.choice(KNOWN_DOMAINS)
        noise = {"ip": ip, "domain": domain}
        instructions.append(f'char noise_ip[] = "{ip}";\n')
        instructions.append(f'char noise_domain[] = "{domain}";\n')
        instructions.append('printf("noise %s %s\\n", noise_ip, noise_domain);\n')

    if "iocs" in features:
        block, uses, used_helpers = _ioc_uses(encoding, rng)
        instructions.extend(block)
        resource_uses.extend(uses)
        helpers.update(used_helpers)

    if "math" in features:
        for variable in factory.create_math_ops_c(n_math):
            instructions.append(variable.full_declaration)
            instructions.append(factory.generate_printf_instructions(variable))

    if "random" in features:
        variable = factory.inject_random_logique(
            [f"{line}\n" for line in includes], False, True)
        if variable:
            instructions.append(variable.full_declaration)
            instructions.append(factory.generate_printf_instructions(variable))

    if "loop" in features:
        loop_vars = (factory.create_random_vars(max(0, n_vars - 1))
                     if n_vars else [])
        for variable in loop_vars:
            instructions.append(variable.full_declaration)
        pool = [factory.generate_printf_instructions(variable)
                for variable in loop_vars]
        if not pool:
            pool = ['printf("loop body\\n");']
        body = factory.gen_instruction(None, pool, instruction_count)
        if loop_break_at is None:
            break_at = rng.randint(1, max(1, len(body)))
        else:
            break_at = loop_break_at
        instructions.append(factory.generate_for_loop(
            includes,
            body,
            loop_step,
            loop_count or rng.randint(3, 8),
            break_at))

    if "buffer_overflow" in features:
        instructions.append(factory.create_buffer_overflow_issues(alloc_size).full_declaration)

    if "double_free" in features:
        instructions.append(factory.create_double_free_issues(n_frees, alloc_size).full_declaration)

    if "uaf" in features:
        instructions.append(factory.generate_free_after_use_vuln(alloc_size).full_declaration)

    if "stack_crash" in features:
        instructions.append(factory.create_stack_crash().full_declaration)

    if "integer_overflow" in features:
        instructions.append(factory.create_integer_overflow_variable().full_declaration)

    if "socket" in features:
        instructions.append(factory.generate_socket_block())

    if sleep_seconds:
        instructions.append(f"Sleep({sleep_seconds * 1000});\n")

    function = factory.generate_functions(
        "void", instructions=instructions, variables=[])
    function_name = function.function_name

    helper_text = ""
    for name in ("rot13", "b64"):
        if name in helpers:
            helper_text += _HELPERS[name]

    if "iocs" in features:
        states = sample_resources.feature_states()
        if not states.get("iocs", {}).get("available"):
            return None, noise, resource_uses, "iocs"

    provenance = []
    if resource_uses:
        provenance.append("resources: iocs<-" + "+".join(
            dict.fromkeys(use["id"] for use in resource_uses)))
    provenance.append(f"encoding: {encoding}")
    if sleep_seconds:
        provenance.append(f"sleep:    {sleep_seconds * 1000} ms")
        provenance.append(f"sleeping {sleep_seconds * 1000} ms")
    comment = (
        "/* Test sample factory output.\n"
        "   Bait literals only: every value is read, never dialled.\n"
        "   This is not a real sample; it exists to be analyzed.\n"
        + "".join(f"   {line}\n" for line in provenance)
        + "*/\n"
    )

    source = _SOURCE_ENV.get_template("c2.j2").render(
        comment=comment,
        imports=includes,
        helpers=helper_text,
        functions=[f"void {function_name}() {{\n{function.code_block}}}\n"],
        main_args="void" if language == "c" else "",
        vars=[],
        function_calls=[f"{function_name}()"],
        print_vals=False,
        variable_name=[],
        add_sleep_time=False,
        random=random,
    )
    return source, noise, resource_uses, None


_SHAPE_LIMITS = {
    "n_math": (0, 8, 2),
    "n_vars": (0, 24, 4),
    "loop_count": (0, 100, 0),
    "loop_step": (1, 10, 1),
    "loop_break_at": (0, 24, None),
    "instruction_count": (1, 12, 1),
    "alloc_size": (1, 1048576, 8),
    "n_frees": (2, 8, 2),
}


def _shape_options(options: dict):
    shape: dict = {}
    for name, (low, high, default) in _SHAPE_LIMITS.items():
        value = options.get(name)
        if value is None:
            shape[name] = default
            continue
        if (isinstance(value, bool) or not isinstance(value, int)
                or value < low or value > high):
            return None, f"{name} must be a whole number between {low} and {high}"
        shape[name] = value
    return shape, None


def compose(language, template=None, features=None, encoding=None,
            sleep_seconds=None, seed=None, n_math=None, n_vars=None,
            loop_count=None, loop_step=None, loop_break_at=None,
            instruction_count=None, alloc_size=None, n_frees=None) -> dict:
    language = (language or "").strip().lower()
    if language not in LANGUAGES:
        return {"ok": False,
                "error": f"unknown language '{language}' - expected one of {', '.join(LANGUAGES)}"}
    features = [f for f in (features or []) if isinstance(f, str)]
    merged: list = []
    template_id = template if isinstance(template, str) and template else None
    if template_id and template_id != CUSTOM_ID:
        found = _template(language, template_id)
        if not found:
            return {"ok": False, "error": f"unknown template '{template_id}' for {language}"}
        merged.extend(found["features"])
    for feature in features:
        if feature not in _allowed_features(language):
            return {"ok": False, "error": f"unknown feature '{feature}' for {language}"}
        if feature not in merged:
            merged.append(feature)
    if encoding is None:
        encoding = "mixed"
    if encoding not in ENCODINGS:
        return {"ok": False,
                "error": f"unknown encoding '{encoding}' - expected one of "
                         + ", ".join(ENCODINGS)}
    if sleep_seconds is None:
        sleep_value = 0
    elif (isinstance(sleep_seconds, bool) or not isinstance(sleep_seconds, int)
          or sleep_seconds < 0 or sleep_seconds > SLEEP_MAX):
        return {"ok": False,
                "error": f"sleep_seconds must be a whole number between 0 and {SLEEP_MAX}"}
    else:
        sleep_value = sleep_seconds
    if seed is None:
        seed = random.SystemRandom().randrange(0, _UINT32 + 1)
    if isinstance(seed, bool) or not isinstance(seed, int):
        return {"ok": False, "error": "seed must be an integer between 0 and 4294967295"}
    if seed < 0 or seed > _UINT32:
        return {"ok": False, "error": "seed must be an integer between 0 and 4294967295"}
    shape, shape_error = _shape_options({
        "n_math": n_math, "n_vars": n_vars, "loop_count": loop_count,
        "loop_step": loop_step, "loop_break_at": loop_break_at,
        "instruction_count": instruction_count, "alloc_size": alloc_size,
        "n_frees": n_frees,
    })
    if shape_error:
        return {"ok": False, "error": shape_error}

    code, noise, uses, refused = _compose_source(
        language, merged, encoding, sleep_value, seed, shape)
    if refused:
        reason = sample_resources.feature_states().get(refused, {}).get("reason")
        return {"ok": False,
                "error": f"the '{refused}' feature cannot be used right now: {reason}"}

    return {
        "ok": True,
        "language": language,
        "template": template_id,
        "features": merged,
        "code": code,
        "noise": noise,
        "resources": uses,
        "encoding": encoding,
        "sleep_seconds": sleep_value,
        "seed": seed,
        "shape": shape,
    }


def compiler_status() -> dict:
    ucrt = Path(getattr(build, "UCRT64", r"")).resolve() if getattr(build, "UCRT64", None) else None
    gcc = ucrt / "bin" / "gcc.exe" if ucrt else None
    gpp = ucrt / "bin" / "g++.exe" if ucrt else None
    if not (gcc and gcc.is_file()):
        found = shutil.which("gcc")
        if not found:
            return {"ok": False,
                    "error": "no C compiler was found",
                    "detail": ("the UCRT64 tree was not found and gcc is not on "
                               "PATH - set IA_MSYS2_UCRT64 to the MSYS2 UCRT64 root")}
        gcc = Path(found)
    if not (gpp and gpp.is_file()):
        found = shutil.which("g++")
        gpp = Path(found) if found else gcc
    return {"ok": True, "gcc": f"{gcc} / {gpp}", "sysroot": str(ucrt) if ucrt else ""}


def upx_status() -> dict:
    path = _repo() / "upx" / "upx.exe"
    if path.is_file():
        return {"ok": True, "path": "upx/upx.exe"}
    return {"ok": False,
            "error": "upx/upx.exe was not found",
            "detail": "packing stays unavailable until the tool is in the tree"}


def templates() -> dict:
    counts = sample_resources.pool_counts()
    states = sample_resources.feature_states(counts)
    available = [name for name in FEATURES
                 if states.get(name, {"available": True})["available"]]
    notes = {name: _FEATURE_NOTES[name] for name in FEATURES}
    unavailable = {name: state["reason"] for name, state in states.items()
                   if not state["available"]}
    return {
        "languages": list(LANGUAGES),
        "features": {language: list(available) for language in LANGUAGES},
        "feature_notes": notes,
        "feature_unavailable": unavailable,
        "pools": counts,
        "templates": _templates(),
        "custom_id": CUSTOM_ID,
        "compiler": compiler_status(),
        "upx": upx_status(),
        "eagle": eagle.status(),
        "encodings": dict(ENCODINGS),
        "sleep_max": SLEEP_MAX,
    }


_STUB_INCLUDE = '#include "EagleVMStub/EagleVMStub.h"'


def _virtualize_source(code: str) -> str:
    """Put EagleVM's begin/end markers around the generated main body.

    Every template renders through c2.j2, so the shape is stable: an include
    block, then ``int main(...) {``, then the calls, then a final return. The
    markers are calls into EagleVMStub.dll; EagleVM finds them by their target
    and virtualises the bytes in between.

    The include goes after the last existing #include so the generated source
    keeps its include block together. A source without a recognisable main is
    refused here rather than compiled into a sample with no virtualised region,
    which EagleVM would reject later with a much less specific error.
    """
    include = _STUB_INCLUDE + "\n"
    lines = code.splitlines(keepends=True)
    insert_at = 0
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#include"):
            insert_at = index + 1
    lines.insert(insert_at, include)
    marked = "".join(lines)

    main = re.search(r"(?m)^\s*int\s+main\s*\([^)]*\)\s*\{", marked)
    if not main:
        raise ValueError("the generated source has no int main to mark")
    marked = (marked[:main.end()] + "\n    fnEagleVMBegin();"
              + marked[main.end():])

    # The final return is the end of the virtualised region. Anchored to the
    # start of a line so a `return` inside a nested helper cannot match.
    returns = list(re.finditer(
        r"(?m)^([ \t]*)return\s+(?:EXIT_SUCCESS|0)\s*;\s*$", marked))
    if not returns:
        raise ValueError("the generated source has no final return to mark")
    last = returns[-1]
    marked = (marked[:last.start()] + f"{last.group(1)}fnEagleVMEnd();\n"
              + marked[last.start():])
    return marked


def _compile(language: str, source: Path, exe: Path, socket: bool,
             include_dirs: list[Path] | None = None,
             libraries: list[str] | None = None) -> tuple[bool, str, str]:
    status = compiler_status()
    if not status.get("ok"):
        return False, "", status.get("error", "no compiler")
    gcc_line = status["gcc"]
    compiler = Path(gcc_line.split(" / ")[0])
    if language == "cpp":
        candidate = compiler.with_name("g++.exe")
        if candidate.is_file():
            compiler = candidate
    argv = [str(compiler), "-O0", "-g", "-static"]
    for folder in include_dirs or []:
        argv += ["-I", str(folder)]
    argv += [str(source), "-o", str(exe)]
    if socket:
        argv.insert(-2, "-lws2_32")
    # Import libraries go after the source: MinGW resolves static archives in
    # command-line order, and a library named before the object that needs it
    # is dropped.
    argv += list(libraries or [])
    proc = _POPEN(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                  text=True, cwd=str(source.parent.parent))
    out, _ = proc.communicate(timeout=180)
    log = out if isinstance(out, str) else (out or "").decode("utf-8", "replace")
    return proc.returncode == 0, log, " ".join(argv)


def _prune(keep: int = SAMPLE_KEEP) -> None:
    samples = _repo() / "samples"
    if not samples.is_dir():
        return
    try:
        from . import samples as samples_module
        protected = samples_module.protected_paths()
    except Exception:
        protected = set()
    pairs = sorted(samples.glob("*.exe"),
                   key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)
    for old in pairs[keep:]:
        if str(old.resolve()) in protected:
            continue
        stem = old.stem
        for candidate in (old, samples / f"{stem}.c", samples / f"{stem}.cpp",
                          samples / f"{stem}.mk"):
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass


def _repo() -> Path:
    try:
        from ..core import config
        return Path(config.REPO)
    except Exception:
        return Path(__file__).resolve().parents[3]


def generate(language, template=None, features=None, name="", encoding=None,
             sleep_seconds=None, upx=False, virtualize=False, seed=None,
             makefile=False, n_math=None, n_vars=None, loop_count=None,
             loop_step=None, loop_break_at=None, instruction_count=None,
             alloc_size=None, n_frees=None) -> dict:
    for label, flag in (("upx", upx), ("virtualize", virtualize),
                        ("makefile", makefile)):
        if not isinstance(flag, bool):
            return {"ok": False,
                    "error": f"{label} must be true or false"}
    composed = compose(language, template, features, encoding, sleep_seconds,
                       seed, n_math, n_vars, loop_count, loop_step,
                       loop_break_at, instruction_count, alloc_size, n_frees)
    if not composed["ok"]:
        return composed

    language = composed["language"]
    extension = "cpp" if language == "cpp" else "c"
    if name:
        if not isinstance(name, str) or not _NAME_RE.match(name):
            return {"ok": False,
                    "error": "name must be letters, digits, dots, dashes or "
                             "underscores - path characters are refused"}
        stem = name
    else:
        base = (composed.get("template") or f"{language}-sample").replace("_", "-")
        stem = f"{base}-{int(time.time() * 1000) % 1000000:06d}"

    repo = _repo()
    samples = repo / "samples"
    samples.mkdir(parents=True, exist_ok=True)
    source = samples / f"{stem}.{extension}"
    exe = samples / f"{stem}.exe"
    source_rel = source.relative_to(repo).as_posix()
    code = composed["code"]

    upx_state = upx_status()
    if upx and not upx_state["ok"]:
        return {"ok": False,
                "error": f"UPX packing was asked for but {upx_state['error']}",
                "detail": upx_state.get("detail", ""),
                "source": source_rel, "code": code}

    include_dirs: list[Path] = []
    libraries: list[str] = []
    if virtualize:
        # Refuse before writing anything: an unbuilt virtualiser is a setup
        # problem, and leaving a half-made sample behind makes it look like a
        # compile failure. The reason names the build button.
        state = eagle.status()
        if not state["ready"]:
            return {"ok": False,
                    "error": "Instruction Virtualisation was asked for but "
                             "EagleVM is not built",
                    "detail": state.get("reason")
                              or "build it from the Utils page first",
                    "source": source_rel, "code": code}
        try:
            code = _virtualize_source(code)
        except ValueError as exc:
            return {"ok": False, "error": str(exc),
                    "source": source_rel, "code": code}
        try:
            eagle_toolchain = eagle.toolchain()
        except RuntimeError as exc:
            return {"ok": False,
                    "error": "Instruction Virtualisation was asked for but "
                             "EagleVM cannot be used",
                    "detail": str(exc), "source": source_rel, "code": code}
        include_dirs = [eagle_toolchain["include"]]
        libraries = ["-L", str(eagle_toolchain["lib"].parent), "-lEagleVMStub"]

    source.write_text(code, encoding="utf-8")
    exe_rel = exe.relative_to(repo).as_posix()

    makefile_rel = None
    make_compiler = "g++" if language == "cpp" else "gcc"
    if makefile:
        makefile_path = samples / f"{stem}.mk"
        make_extra = ""
        if virtualize:
            make_extra = (f' -I "{include_dirs[0]}"'
                          f' -L "{libraries[1]}" -lEagleVMStub')
        makefile_path.write_text(
            f"{stem}.exe: {stem}.{extension}\n"
            f"\t{make_compiler} -O0 -g -static{make_extra} "
            f"{stem}.{extension} -o {stem}.exe\n",
            encoding="utf-8")
        makefile_rel = makefile_path.relative_to(repo).as_posix()

    ok, log, command = _compile(language, source, exe,
                                "socket" in composed["features"],
                                include_dirs=include_dirs,
                                libraries=libraries)
    if not ok:
        detail = compiler_status()
        if not detail.get("ok"):
            return {"ok": False,
                    "error": "the sample was not compiled: the compiler was not found",
                    "detail": detail.get("detail", ""),
                    "source": source_rel, "code": code,
                    "makefile": makefile_rel}
        return {"ok": False,
                "error": "compile failed",
                "detail": "see the compiler output",
                "log": log, "command": command,
                "source": source_rel, "code": code,
                "makefile": makefile_rel}

    virtualized = None
    if virtualize:
        try:
            protected, vm_log = eagle.virtualize(exe, cwd=samples)
        except RuntimeError as exc:
            return {"ok": False,
                    "error": "EagleVM could not virtualise the sample",
                    "detail": str(exc),
                    "log": (log + "\n" + str(exc)).strip(),
                    "command": command,
                    "source": source_rel, "code": code,
                    "makefile": makefile_rel}
        log = (log + "\n" + vm_log).strip()
        virtualized = {"from": exe.name, "to": protected.name,
                       "log": vm_log}
        exe = protected
        exe_rel = exe.relative_to(repo).as_posix()

    result = {
        "ok": True,
        "source": source_rel,
        "exe": exe_rel,
        "bytes": exe.stat().st_size,
        "code": code,
        "log": log,
        "command": command,
        "makefile": makefile_rel,
        "noise": composed["noise"],
        "resources": composed["resources"],
        "encoding": composed["encoding"],
        "sleep_seconds": composed["sleep_seconds"],
        "seed": composed["seed"],
        "shape": composed["shape"],
        "virtualized": virtualized,
        "flags": {"upx": bool(upx), "virtualize": bool(virtualize),
                  "makefile": bool(makefile)},
    }

    if upx:
        before = exe.stat().st_size
        pack = _POPEN([str(repo / upx_state["path"]), "--best", "-q", str(exe)],
                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                      text=True)
        out, _ = pack.communicate(timeout=180)
        pack_log = out if isinstance(out, str) else (out or "").decode("utf-8", "replace")
        if pack.returncode != 0:
            return {"ok": False,
                    "error": "UPX failed to pack the sample",
                    "detail": pack_log.strip() or "the packer returned an error",
                    "log": pack_log,
                    "exe": exe_rel,
                    "source": source_rel,
                    "code": code,
                    "flags": {"upx": True, "virtualize": bool(virtualize),
                              "makefile": bool(makefile)}}
        result["log"] = (log + "\n" + pack_log).strip()
        after = exe.stat().st_size
        result["packed"] = {
            "before": before,
            "after": after,
            "ratio": round(after / before, 3) if before else None,
        }

    _prune()
    return result


if __name__ == "__main__":
    demo = compose("c", "c_strings", ["noise", "math", "random"])
    print(demo.get("code", demo))
