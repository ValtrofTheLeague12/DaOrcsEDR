"""Generates a minimal but structurally valid Mach-O 64-bit executable.

Fixture for the analyzer's Mach-O path (format detection, section table,
import symbols). No cross-compiler is available here, so the container is
assembled by hand with struct packing instead of clang -target.

The binary is never executed (it cannot run on Windows/Linux); it exists only
as analysis input. Indicator strings sit in __cstring so the string and IOC
scanners see them, and the symbol table carries the imports a real Mach-O
sample would reference.
"""
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
CPU_SUBTYPE_X86_ALL = 3
MH_EXECUTE = 2
MH_PIE = 0x00200000
MH_NOUNDEFS = 0x00800000
MH_DYLDLINK = 0x00000004

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_MAIN = 0x80000028
LC_LOAD_DYLINKER = 0x0E

S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

HEADER_SIZE = 32
SECTION_SIZE = 80


def align8(n):
    return (n + 7) & ~7


def fixed(name):
    b = name.encode()[:16]
    return b + b"\x00" * (16 - len(b))


def segment_cmd(name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags):
    size = 72 + nsects * SECTION_SIZE
    return struct.pack("<II16sQQQQIIII", LC_SEGMENT_64, size, fixed(name),
                       vmaddr, vmsize, fileoff, filesize,
                       maxprot, initprot, nsects, flags)


def section_cmd(sectname, segname, addr, size, offset, align, flags, r1=0, r2=0, r3=0):
    # section_64: sectname16 segname16 addr Q size Q offset I align I
    #             reloff I nreloc I flags I reserved1..3 III
    return struct.pack("<16s16sQQIIIIIIII", fixed(sectname), fixed(segname),
                       addr, size, offset, align, 0, 0, flags, r1, r2, r3)





# Same indicator set the C++ fixture carries, so both samples exercise the
# string/IOC heuristics identically.
CSTRINGS = [
    b"malicious-c2.evil.invalid",
    b"http://malicious-c2.evil.invalid/gate.php",
    b"https://cdn-update-service.evil.invalid/payload",
    b"exfildrop7kq3mz5n6o2x4p.onion",
    b"203.0.113.77",
    b"AKIAIOSFODNN7EXAMPLE",
    b"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) FakeC2/1.0",
    b"VMwareVMware", b"VBoxVBoxVBox", b"QEMU", b"x64dbg", b"frida",
    b"ptrace", b"VirtualAllocEx", b"WriteProcessMemory",
    b"CreateRemoteThread", b"SetWindowsHookEx",
    b"/Library/LaunchDaemons/com.example.helper.plist",
    b"SMJobBless", b"NSTask", b"SLEEP_MASK", b"\x00",
]

# Undefined (imported) symbols: what a real Mach-O sample would pull in.
IMPORTS = [
    "_dlsym", "_ptrace", "_sysctl", "_execve", "_fork", "_posix_spawn",
    "_socket", "_connect", "_send", "_recv", "_mmap", "_mprotect",
    "_NSTask", "_SecKeyCreateRandomKey", "_CCCrypt", "_objc_getClass",
    "_system", "_popen", "_dlopen",
]

TEXT_VM = 0x100000000
DATA_VM = 0x100001000
LINKEDIT_VM = 0x100002000



def build():
    cstr = b"".join(CSTRINGS)
    text_code = b"\x90" * 64 + b"\xc3"          # nops + ret
    data_blob = b"\xde\xad\xbe\xef" * 16

    linker_name = b"/usr/lib/dyld"
    lc_load_dylinker = struct.pack("<II", LC_LOAD_DYLINKER, 24 + len(linker_name))
    lc_load_dylinker += struct.pack("<I", 24) + linker_name

    text_sections = [
        section_cmd("__text", "__TEXT", TEXT_VM, len(text_code), 0, 4,
                    S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS),
        section_cmd("__cstring", "__TEXT", TEXT_VM + 0x1000, len(cstr), 0, 0, 0),
    ]
    text_seg = segment_cmd("__TEXT", TEXT_VM, 0x2000, 0, 0, 7, 5, len(text_sections), 0)
    text_seg += b"".join(text_sections)

    offset = HEADER_SIZE
    text_seg_off = offset
    offset += align8(len(text_seg))
    main_off = offset
    offset += 24
    dylinker_off = offset
    offset += align8(len(lc_load_dylinker))
    text_code_off = offset
    offset += len(text_code)
    cstring_off = offset
    offset += len(cstr)
    text_filesize = align8(offset)

    data_sections = [
        section_cmd("__data", "__DATA", DATA_VM, len(data_blob), 0, 3, 0),
        section_cmd("__const", "__DATA", DATA_VM + 0x100, 16, 0, 3, 0),
    ]
    data_seg = segment_cmd("__DATA", DATA_VM, 0x1000, 0, 0, 7, 3, len(data_sections), 0)
    data_seg += b"".join(data_sections)
    data_seg_off = text_filesize
    data_blob_off = align8(data_seg_off + len(data_seg))

    # __LINKEDIT: nlist symbol table of undefined imports + string table.
    stroff_rel = 1
    strtab = b"\x00" + b"".join(s.encode() + b"\x00" for s in IMPORTS)
    nlist = []
    for s in IMPORTS:
        nlist.append(struct.pack("<IBBHQ", stroff_rel, 0x01, 0, 0, 0))  # N_UNDF
        stroff_rel += len(s) + 1
    symtab = b"".join(nlist)

    linkedit_fileoff = align8(data_blob_off + len(data_blob))
    symoff = linkedit_fileoff
    stroff = symoff + len(symtab)
    strsize = len(strtab)

    linkedit_seg = segment_cmd("__LINKEDIT", LINKEDIT_VM, 0x1000,
                               linkedit_fileoff, strsize + len(symtab), 7, 1, 0, 0)
    lc_symtab = struct.pack("<IIIIII", LC_SYMTAB, 24, symoff, len(nlist), stroff, strsize)
    lc_dysymtab = struct.pack("<II" + "I" * 18, LC_DYSYMTAB, 80,
                              0, 0, 0, len(nlist), 0, 0, 0, 0,
                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    lc_main = struct.pack("<IIQQ", LC_MAIN, 24, text_code_off, 0)

    # Seven load commands: __TEXT segment, LC_MAIN, LC_LOAD_DYLINKER,
    # __DATA segment, __LINKEDIT segment, LC_SYMTAB, LC_DYSYMTAB. An
    # undercount makes LIEF walk past the command table into __text and report
    # "Command 'UNKNOWN' (0x90909090) not parsed".
    ncmds = 7
    sizeofcmds = (len(text_seg) + len(lc_load_dylinker) + len(lc_main) +
                  len(data_seg) + len(linkedit_seg) + len(lc_symtab) + len(lc_dysymtab))

    header = struct.pack("<IiiIIIII", MH_MAGIC_64, CPU_TYPE_X86_64,
                         CPU_SUBTYPE_X86_ALL, MH_EXECUTE, ncmds, sizeofcmds,
                         MH_PIE | MH_NOUNDEFS | MH_DYLDLINK, 0)

    out = bytearray(header)
    out += b"\x00" * (text_seg_off - len(out)); out += text_seg
    out += b"\x00" * (main_off - len(out));     out += lc_main
    out += b"\x00" * (dylinker_off - len(out)); out += lc_load_dylinker
    out += b"\x00" * (text_code_off - len(out)); out += text_code
    out += b"\x00" * (cstring_off - len(out));  out += cstr
    out += b"\x00" * (data_seg_off - len(out)); out += data_seg
    out += b"\x00" * (data_blob_off - len(out)); out += data_blob
    out += b"\x00" * (linkedit_fileoff - len(out))
    out += linkedit_seg + lc_symtab + lc_dysymtab
    out += b"\x00" * (symoff - len(out)); out += symtab
    out += b"\x00" * (stroff - len(out)); out += strtab
    return bytes(out)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "suspicious_sample.macho"
    blob = build()
    with open(target, "wb") as fh:
        fh.write(blob)
    print("wrote %s (%d bytes, magic=0x%08x)" % (
        target, len(blob), struct.unpack_from("<I", blob, 0)[0]))
