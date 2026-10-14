#!/usr/bin/env python3
"""
qiling_harness_pe.py (v5) - Qiling 1.4.6 Windows PE malware intel collector

Fixes in v5:
  - Qiling 1.4.6 "cannot import ULONG from qiling.os.core" compat shim
  - _safe_write() wrapper around every ql.mem.write() (no more crashes on bad pointers)
  - safe_hook_code() with base+size overflow guard
  - Broken-API stubber: register CALL stubs for APIs Qiling fails to import
  - All v4 features retained (EXIT-arg logging, YARA, PEB patch, wait hooks, report.md)

Usage:
  python3 qiling_harness_pe.py [--rootfs R] [--out report.zip] [--timeout S]
                               [--max-insn N] [--verbose ...]
                               [--yara-rules DIR_OR_FILE] [--no-peb-patch]
                               sample.exe [sample args...]
"""

# ---------------------------------------------------------------------------
# 0. Qiling 1.4.6 compatibility shim  (MUST run before importing qiling.os.*)
# ---------------------------------------------------------------------------
import ctypes as _ctypes

try:
    import qiling.os.core as _qcore
    _SHIM_TYPES = {
        "ULONG":      _ctypes.c_uint32,
        "ULONGLONG":  _ctypes.c_uint64,
        "DWORD":      _ctypes.c_uint32,
        "DWORD32":    _ctypes.c_uint32,
        "DWORD64":    _ctypes.c_uint64,
        "WORD":       _ctypes.c_uint16,
        "BYTE":       _ctypes.c_uint8,
        "BOOLEAN":    _ctypes.c_uint8,
        "HANDLE":     _ctypes.c_void_p,
        "LPVOID":     _ctypes.c_void_p,
        "PVOID":      _ctypes.c_void_p,
        "SIZE_T":     _ctypes.c_size_t,
        "ULONG_PTR":  _ctypes.c_size_t,
        "LONG_PTR":   _ctypes.c_ssize_t,
        "NTSTATUS":   _ctypes.c_int32,
        "WCHAR":      _ctypes.c_wchar,
        "UINT":       _ctypes.c_uint32,
        "INT":        _ctypes.c_int32,
        "SHORT":      _ctypes.c_int16,
        "USHORT":     _ctypes.c_uint16,
        "LARGE_INTEGER": _ctypes.c_int64,
    }
    for _n, _t in _SHIM_TYPES.items():
        if not hasattr(_qcore, _n):
            setattr(_qcore, _n, _t)
    # Also patch qiling.os.windows.* modules that may import these names directly
    try:
        import qiling.os.windows.const as _wconst
        for _n, _t in _SHIM_TYPES.items():
            if not hasattr(_wconst, _n):
                setattr(_wconst, _n, _t)
    except Exception:
        pass
except Exception:
    # qiling not installed yet — let the real import fail with a clean message
    pass
# ---------------------------------------------------------------------------

import argparse
import collections
import hashlib
import ipaddress
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import zipfile
import traceback

try:
    from qiling import Qiling
    from qiling.const import QL_VERBOSE, QL_INTERCEPT
    HAVE_QILING = True
    QILING_IMPORT_ERROR = None
except Exception as e:
    HAVE_QILING = False
    QILING_IMPORT_ERROR = e
    Qiling = None
    QL_VERBOSE = None
    QL_INTERCEPT = None

# --- optional YARA ---
try:
    import yara
    HAVE_YARA = True
except Exception:
    HAVE_YARA = False

if HAVE_QILING:
    ENTER, EXIT, CALL = QL_INTERCEPT.ENTER, QL_INTERCEPT.EXIT, QL_INTERCEPT.CALL
else:
    ENTER = EXIT = CALL = None

TOOL_VERSION = "qiling_harness_pe v5"
MAX_EVENTS = 2_000_000

# --- PE arch pre-check (stdlib only, runs before Qiling) -------------------
SUPPORTED_MACHINES = {0x014C: "x86", 0x8664: "x64"}
ROOTFS_ARCH_DIRS = {"x86": "x86_windows", "x64": "x8664_windows"}


def pe_machine(path):
    """Return the PE COFF Machine field, or None if not a PE."""
    with open(path, "rb") as f:
        if f.read(2) != b"MZ":
            return None
        f.seek(0x3C)
        e_lfanew = f.read(4)
        if len(e_lfanew) != 4:
            return None
        f.seek(struct.unpack("<I", e_lfanew)[0])
        if f.read(4) != b"PE\x00\x00":
            return None
        machine = f.read(2)
        if len(machine) != 2:
            return None
        return struct.unpack("<H", machine)[0]


def check_sample_arch(sample, rootfs):
    """Fail fast unless sample is an x86/x64 PE matching the given rootfs.

    Returns (arch, resolved_rootfs) where resolved_rootfs is the
    arch-specific subfolder Qiling 1.4.6 needs (it does not auto-append it).
    """
    machine = pe_machine(sample)
    if machine is None:
        sys.exit(f"[-] {sample}: not a PE file (missing MZ/PE headers)")
    arch = SUPPORTED_MACHINES.get(machine)
    if arch is None:
        sys.exit(f"[-] unsupported PE machine 0x{machine:04X} - only x86 "
                 f"(0x14C) and x64 (0x8664) Windows binaries are supported")
    rf_name = os.path.basename(os.path.normpath(rootfs))
    want = ROOTFS_ARCH_DIRS[arch]
    if rf_name in ROOTFS_ARCH_DIRS.values():
        if rf_name != want:
            have = "x64" if rf_name == "x8664_windows" else "x86"
            sys.exit(f"[-] sample is {arch} but --rootfs points at '{rf_name}' "
                     f"({have} system files) - pass the parent rootfs dir "
                     f"or '{want}' instead")
        resolved = os.path.normpath(rootfs)
    else:
        child = os.path.join(rootfs, want)
        if not os.path.isdir(child):
            found = ", ".join(sorted(
                d for d in (os.path.join(rootfs, x)
                            for x in ROOTFS_ARCH_DIRS.values())
                if os.path.isdir(d))) or "none"
            sys.exit(f"[-] rootfs '{rootfs}' has no {want}/ subfolder "
                     f"(arch dirs found: {found})")
        resolved = os.path.normpath(child)
    print(f"[+] sample arch: {arch} (machine 0x{machine:04X})")
    print(f"[+] rootfs resolved for {arch}: {resolved}")
    return arch, resolved


# ----------------------------------------------------------------------------
# Global state
# ----------------------------------------------------------------------------
class State:
    t0 = 0.0
    log = None
    jsonl = None
    workdir = None
    zip_path = None
    arch64 = True
    dumped = {}
    dump_index = []
    watched = set()
    counts = collections.Counter()
    tags = collections.Counter()
    tick = 0x00124A10
    skipped_ms = 0
    events_written = 0
    yara_rules = None
    yara_hits = []
    timeline = []
    iocs_seen = set()
    peb_patched = False
    sample_path = None
    sample_hashes = {}
    rootfs = None
    verbose = None
    api_errors = collections.Counter()


st = State()

ATTACK = {
    "inject":   "T1055 Process Injection",
    "hollow":   "T1055.012 Process Hollowing",
    "antidbg":  "T1622 Debugger Evasion",
    "antivm":   "T1497.001 System Checks (VM/Sandbox Evasion)",
    "timing":   "T1497.003 Time Based Evasion",
    "persist":  "T1547 / T1543 Persistence",
    "net":      "T1071 / T1105 Application Layer Protocol / Ingress Tool Transfer",
    "exec":     "T1106 Native API / T1059 Execution",
    "load":     "T1027.007 Dynamic API Resolution",
    "discover": "T1082 / T1057 / T1033 Discovery",
    "crypto":   "T1027 / T1573 Obfuscation / Encrypted Channel",
    "file":     "T1105 Ingress Tool Transfer / T1074 Data Staged",
    "evade":    "T1622 / T1497 Evasion",
    "yara":     "Signature match",
    "peb":      "T1622 Debugger Evasion (direct PEB)",
    "wait":     "T1497.003 Time Based Evasion",
}


def rec(kind, msg, **data):
    t = time.time() - st.t0
    line = f"[{t:9.3f}] [{kind}] {msg}"
    try:
        print(line)
    except Exception:
        pass
    try:
        if st.log:
            st.log.write(line + "\n")
    except Exception:
        pass
    if st.events_written < MAX_EVENTS:
        try:
            if st.jsonl:
                st.jsonl.write(json.dumps({"t": round(t, 3), "kind": kind, "msg": msg, **data}, default=str) + "\n")
        except Exception:
            pass
        st.events_written += 1
    if kind not in ("ioc",):
        st.timeline.append({"t": round(t, 3), "kind": kind, "msg": msg})


# ----------------------------------------------------------------------------
# Safe memory helpers
# ----------------------------------------------------------------------------
def ptrsize():
    return 8 if st.arch64 else 4


def safe_read(ql, addr, size):
    """Page-by-page read; returns whatever was readable (possibly b'')."""
    if not addr or size <= 0:
        return b""
    buf, off = bytearray(), 0
    while off < size:
        n = min(0x1000 - ((addr + off) & 0xFFF), size - off)
        try:
            buf += bytes(ql.mem.read(addr + off, n))
        except Exception:
            break
        off += n
    return bytes(buf)


def safe_write(ql, addr, data):
    """Write bytes, swallow any mapping error. Returns True on success."""
    if not addr or not data:
        return False
    try:
        ql.mem.write(addr, bytes(data))
        return True
    except Exception:
        return False


def wint(ql, addr, val, size=None):
    """Safe integer write."""
    if not addr:
        return
    try:
        sz = size or ptrsize()
        safe_write(ql, addr, int(val).to_bytes(sz, "little", signed=False))
    except Exception:
        pass


def read_str(ql, v, wide=False, limit=260):
    if isinstance(v, str):
        return v
    if not v:
        return ""
    step = 2 if wide else 1
    try:
        raw = safe_read(ql, v, limit * step)
    except Exception:
        return ""
    if wide:
        end = raw.find(b"\x00\x00")
        if end >= 0 and end % 2 == 0:
            raw = raw[:end]
        try:
            return raw.decode("utf-16-le", "replace")
        except Exception:
            return ""
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    return raw.decode("latin-1", "replace")


def raw_param(ql, idx):
    try:
        return ql.os.fcall.cc.getRawParam(idx)
    except Exception:
        return 0


def get_args(ql, params, spec):
    out = {}
    for i, (name, _) in enumerate(spec):
        v = params.get(name) if isinstance(params, dict) else None
        out[name] = v if v is not None else raw_param(ql, i)
    return out


def fmt(ql, v, kind):
    try:
        if kind in ("s", "w"):
            return repr(read_str(ql, v, kind == "w"))
        if kind == "n":
            if isinstance(v, int) and v <= 0xFFFF:
                return f"#ordinal {v}"
            return repr(read_str(ql, v))
        return f"{int(v):#x}"
    except Exception:
        return repr(v)


def safe_hook_code(ql, cb, base, size):
    """Install a code hook with overflow / invalid-range guard."""
    if not base or size <= 0:
        return None
    try:
        end = base + size - 1
        if end <= base:
            return None
        return ql.hook_code(cb, begin=base, end=end)
    except Exception as e:
        rec("error", f"hook_code failed @ {base:#x}+{size:#x}: {type(e).__name__}: {e}")
        return None


# ----------------------------------------------------------------------------
# Strings / IOCs
# ----------------------------------------------------------------------------
def scan_strings(data):
    out = [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{6,}", data)]
    out += [m.group().decode("utf-16-le", "replace") for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", data)]
    return out


RE_URL = re.compile(r"https?://[\x21-\x7e]{4,200}")
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
RE_BTC = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")
RE_REGKEY = re.compile(r"\b(?:SOFTWARE|SYSTEM|SAM|SECURITY|HARDWARE)[\\A-Za-z0-9_\-{}. ]{4,200}", re.I)
RE_MUTEX = re.compile(r"\b(?:Global|Local)\\[A-Za-z0-9_\-{}.!@#$%^&*()]{3,80}")


def _bad_ip(ip):
    try:
        a = ipaddress.IPv4Address(ip)
    except Exception:
        return True
    return (a.is_private or a.is_loopback or a.is_multicast or a.is_reserved or a.is_link_local)


def iocs(strings, include_domains=True):
    found = set()
    skip_ext = (".dll", ".exe", ".sys", ".png", ".jpg", ".gif",
                ".html", ".htm", ".txt", ".ini", ".dat", ".bin",
                ".tmp", ".log", ".xml", ".json", ".pdb", ".lib")
    for s in strings:
        try:
            found.update(RE_URL.findall(s))
            found.update(RE_EMAIL.findall(s))
            found.update(RE_BTC.findall(s))
            found.update(RE_REGKEY.findall(s))
            found.update(RE_MUTEX.findall(s))
            for ip in RE_IP.findall(s):
                if not _bad_ip(ip):
                    found.add(ip)
            if include_domains:
                for d in RE_DOMAIN.findall(s):
                    low = d.lower()
                    if any(low.endswith(t) for t in skip_ext):
                        continue
                    if 4 < len(low) < 80:
                        found.add(low)
        except Exception:
            continue
    return sorted(found)


def looks_like_pe(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    try:
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except Exception:
        return False
    return lfanew + 4 <= len(data) and data[lfanew:lfanew + 4] == b"PE\x00\x00"


def yara_scan(path, data):
    if not st.yara_rules:
        return []
    hits = []
    try:
        matches = st.yara_rules.match(data=data)
        for m in matches:
            st.tags["yara"] += 1
            hits.append(m.rule)
            rec("yara", f"MATCH {m.rule} in {os.path.basename(path)}",
                rule=m.rule, namespace=getattr(m, "namespace", ""),
                tags=list(getattr(m, "tags", [])), path=path)
    except Exception as e:
        rec("error", f"yara scan failed on {path}: {type(e).__name__}: {e}")
    return hits


def dump_region(ql, addr, size, tag, limit=0x100000):
    if not addr:
        return
    try:
        size = int(size) or 0x1000
    except Exception:
        size = 0x1000
    data = safe_read(ql, addr, max(0x100, min(size, limit)))
    if not data:
        rec("dump", f"unreadable {addr:#x}+{size:#x} ({tag})")
        return
    h = hashlib.sha256(data).hexdigest()
    if h in st.dumped:
        return
    ext = "pe" if looks_like_pe(data) else "bin"
    rel = os.path.join("dumps", f"{tag}_{addr:#x}_{h[:8]}.{ext}")
    path = os.path.join(st.workdir, rel)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
    except Exception as e:
        rec("error", f"failed to write dump {rel}: {e}")
        return
    st.dumped[h] = rel
    st.dump_index.append({"sha256": h, "path": rel, "size": len(data),
                          "pe": ext == "pe", "tag": tag, "addr": addr})

    strings = scan_strings(data)
    try:
        with open(path + ".strings.txt", "w", encoding="utf-8", errors="replace") as f:
            f.write("\n".join(strings))
    except Exception:
        pass

    rec("dump",
        f"{len(data):#x} bytes @ {addr:#x} -> {rel}" + ("  [embedded PE!]" if ext == "pe" else ""),
        sha256=h, path=rel, pe=(ext == "pe"))

    yara_scan(path, data)

    for ioc in iocs(strings)[:50]:
        if ioc not in st.iocs_seen:
            st.iocs_seen.add(ioc)
            rec("ioc", f"{ioc}   (from {os.path.basename(rel)})", ioc=ioc, source=rel)


def watch_exec(ql, base, size, why):
    if not base or base in st.watched:
        return
    st.watched.add(base)
    try:
        size = int(size) or 0x1000
    except Exception:
        size = 0x1000
    box = []

    def first_exec(q, address, _sz):
        try:
            if box:
                q.hook_del(box[0])
        except Exception:
            pass
        rec("exec", f"FIRST EXECUTION in dynamic region {base:#x} ({why}) at {address:#x}", pc=address)
        dump_region(q, base, size, "exec")

    h = safe_hook_code(ql, first_exec, base, size)
    if h:
        box.append(h)


# ----------------------------------------------------------------------------
# PEB patch
# ----------------------------------------------------------------------------
def patch_peb(ql):
    peb = 0
    try:
        peb = getattr(ql.loader, "peb", 0) or 0
    except Exception:
        peb = 0
    if not peb:
        try:
            seg = ql.arch.regs.gs if st.arch64 else ql.arch.regs.fs
            raw = safe_read(ql, seg + (0x60 if st.arch64 else 0x30), ptrsize())
            if len(raw) == ptrsize():
                peb = int.from_bytes(raw, "little")
        except Exception:
            peb = 0
    if not peb:
        rec("peb", "could not locate PEB; skipping PEB patch")
        return

    safe_write(ql, peb + 0x02, b"\x00")                       # BeingDebugged
    ntglobal_off = 0xBC if st.arch64 else 0x68
    safe_write(ql, peb + ntglobal_off, (0).to_bytes(4, "little"))

    process_heap_off = 0x30 if st.arch64 else 0x18
    raw = safe_read(ql, peb + process_heap_off, ptrsize())
    if len(raw) == ptrsize():
        heap = int.from_bytes(raw, "little")
        if heap:
            if st.arch64:
                flags_off, force_off = 0x70, 0x74
            else:
                flags_off, force_off = 0x40, 0x44
            safe_write(ql, heap + flags_off, (2).to_bytes(4, "little"))
            safe_write(ql, heap + force_off, (0).to_bytes(4, "little"))

    st.peb_patched = True
    st.tags["peb"] += 1
    rec("peb", f"PEB patched @ {peb:#x}: BeingDebugged=0 NtGlobalFlag=0 HeapFlags=2 ForceFlags=0")


# ----------------------------------------------------------------------------
# Trace table
# ----------------------------------------------------------------------------
TRACE = {
    "VirtualAlloc": ("inject", [("lpAddress", "x"), ("dwSize", "x"), ("flAllocationType", "x"), ("flProtect", "x")]),
    "VirtualAllocEx": ("inject", [("hProcess", "x"), ("lpAddress", "x"), ("dwSize", "x"), ("flAllocationType", "x"), ("flProtect", "x")]),
    "VirtualProtect": ("inject", [("lpAddress", "x"), ("dwSize", "x"), ("flNewProtect", "x"), ("lpflOldProtect", "x")]),
    "VirtualProtectEx": ("inject", [("hProcess", "x"), ("lpAddress", "x"), ("dwSize", "x"), ("flNewProtect", "x"), ("lpflOldProtect", "x")]),
    "WriteProcessMemory": ("inject", [("hProcess", "x"), ("lpBaseAddress", "x"), ("lpBuffer", "x"), ("nSize", "x")]),
    "ReadProcessMemory": ("inject", [("hProcess", "x"), ("lpBaseAddress", "x"), ("lpBuffer", "x"), ("nSize", "x")]),
    "CreateRemoteThread": ("inject", [("hProcess", "x"), ("lpThreadAttributes", "x"), ("dwStackSize", "x"), ("lpStartAddress", "x"), ("lpParameter", "x"), ("dwCreationFlags", "x")]),
    "CreateRemoteThreadEx": ("inject", [("hProcess", "x"), ("lpThreadAttributes", "x"), ("dwStackSize", "x"), ("lpStartAddress", "x"), ("lpParameter", "x"), ("dwCreationFlags", "x")]),
    "CreateThread": ("inject", [("lpThreadAttributes", "x"), ("dwStackSize", "x"), ("lpStartAddress", "x"), ("lpParameter", "x"), ("dwCreationFlags", "x")]),
    "QueueUserAPC": ("inject", [("pfnAPC", "x"), ("hThread", "x"), ("dwData", "x")]),
    "NtQueueApcThread": ("inject", [("ThreadHandle", "x"), ("ApcRoutine", "x"), ("ApcArgument1", "x")]),
    "NtWriteVirtualMemory": ("inject", [("ProcessHandle", "x"), ("BaseAddress", "x"), ("Buffer", "x"), ("NumberOfBytesToWrite", "x")]),
    "NtAllocateVirtualMemory": ("inject", [("ProcessHandle", "x"), ("BaseAddress", "x"), ("ZeroBits", "x"), ("RegionSize", "x"), ("AllocationType", "x"), ("Protect", "x")]),
    "NtProtectVirtualMemory": ("inject", [("ProcessHandle", "x"), ("BaseAddress", "x"), ("RegionSize", "x"), ("NewProtect", "x")]),
    "NtCreateThreadEx": ("inject", [("ThreadHandle", "x"), ("DesiredAccess", "x"), ("ObjectAttributes", "x"), ("ProcessHandle", "x"), ("StartRoutine", "x"), ("Argument", "x"), ("CreateFlags", "x")]),
    "RtlCreateUserThread": ("inject", [("ProcessHandle", "x"), ("SecurityDescriptor", "x"), ("CreateSuspended", "x"), ("StackZeroBits", "x"), ("StackReserved", "x"), ("StackCommit", "x"), ("StartAddress", "x"), ("StartParameter", "x")]),
    "NtUnmapViewOfSection": ("hollow", [("ProcessHandle", "x"), ("BaseAddress", "x")]),
    "ResumeThread": ("hollow", [("hThread", "x")]),
    "SetThreadContext": ("hollow", [("hThread", "x"), ("lpContext", "x")]),
    "GetThreadContext": ("hollow", [("hThread", "x"), ("lpContext", "x")]),
    "GetProcAddress": ("load", [("hModule", "x"), ("lpProcName", "n")]),
    "LdrGetProcedureAddress": ("load", [("ModuleHandle", "x"), ("ProcedureName", "x"), ("Ordinal", "x")]),
    "WinExec": ("exec", [("lpCmdLine", "s"), ("uCmdShow", "x")]),
    "IsDebuggerPresent": ("antidbg", []),
    "CheckRemoteDebuggerPresent": ("antidbg", [("hProcess", "x"), ("pbDebuggerPresent", "x")]),
    "NtQueryInformationProcess": ("antidbg", [("ProcessHandle", "x"), ("ProcessInformationClass", "x"), ("ProcessInformation", "x"), ("ProcessInformationLength", "x")]),
    "NtSetInformationThread": ("antidbg", [("ThreadHandle", "x"), ("ThreadInformationClass", "x")]),
    "GetTickCount": ("timing", []),
    "GetTickCount64": ("timing", []),
    "QueryPerformanceCounter": ("timing", [("lpPerformanceCount", "x")]),
    "QueryPerformanceFrequency": ("timing", [("lpFrequency", "x")]),
    "NtDelayExecution": ("timing", [("Alertable", "x"), ("DelayInterval", "x")]),
    "GetSystemInfo": ("antivm", [("lpSystemInfo", "x")]),
    "GetAdaptersInfo": ("antivm", [("pAdapterInfo", "x"), ("pOutBufLen", "x")]),
    "GlobalMemoryStatusEx": ("antivm", [("lpBuffer", "x")]),
    "GetCursorPos": ("antivm", [("lpPoint", "x")]),
    "CreateToolhelp32Snapshot": ("discover", [("dwFlags", "x"), ("th32ProcessID", "x")]),
    "Process32First": ("discover", [("hSnapshot", "x"), ("lppe", "x")]),
    "Process32Next": ("discover", [("hSnapshot", "x"), ("lppe", "x")]),
    "Process32FirstW": ("discover", [("hSnapshot", "x"), ("lppe", "x")]),
    "Process32NextW": ("discover", [("hSnapshot", "x"), ("lppe", "x")]),
    "IsWow64Process": ("discover", [("hProcess", "x")]),
    "GetForegroundWindow": ("discover", []),
    "GetAsyncKeyState": ("discover", [("vKey", "x")]),
    "connect": ("net", [("s", "x"), ("name", "x"), ("namelen", "x")]),
    "WSAConnect": ("net", [("s", "x"), ("name", "x"), ("namelen", "x")]),
    "send": ("net", [("s", "x"), ("buf", "x"), ("len", "x"), ("flags", "x")]),
    "recv": ("net", [("s", "x"), ("buf", "x"), ("len", "x"), ("flags", "x")]),
    "getaddrinfo": ("net", [("pNodeName", "s"), ("pServiceName", "s")]),
    "gethostbyname": ("net", [("name", "s")]),
    "WinHttpConnect": ("net", [("hSession", "x"), ("pswzServerName", "w"), ("nServerPort", "x")]),
    "BCryptDecrypt": ("crypto", [("hKey", "x"), ("pbInput", "x"), ("cbInput", "x")]),
    "BCryptEncrypt": ("crypto", [("hKey", "x"), ("pbInput", "x"), ("cbInput", "x")]),
    "CryptDecrypt": ("crypto", [("hKey", "x"), ("hHash", "x"), ("Final", "x"), ("dwFlags", "x"), ("pbData", "x")]),
    "CryptEncrypt": ("crypto", [("hKey", "x"), ("hHash", "x"), ("Final", "x"), ("dwFlags", "x"), ("pbData", "x")]),
    "CryptStringToBinary": ("crypto", [("pszString", "s"), ("cchString", "x"), ("dwFlags", "x")]),
    "CryptUnprotectData": ("crypto", [("pDataIn", "x"), ("szDataDescr", "x"), ("pOptionalEntropy", "x")]),
    "WriteFile": ("file", [("hFile", "x"), ("lpBuffer", "x"), ("nNumberOfBytesToWrite", "x")]),
    "SetWindowsHookEx": ("discover", [("idHook", "x"), ("lpfn", "x"), ("hMod", "x")]),
}

_AW = {
    "CreateProcess": ("exec", [("lpApplicationName", "t"), ("lpCommandLine", "t"), ("lpProcessAttributes", "x"), ("lpThreadAttributes", "x"), ("bInheritHandles", "x"), ("dwCreationFlags", "x")]),
    "ShellExecute": ("exec", [("hwnd", "x"), ("lpOperation", "t"), ("lpFile", "t"), ("lpParameters", "t")]),
    "ShellExecuteEx": ("exec", [("pExecInfo", "x")]),
    "LoadLibrary": ("load", [("lpLibFileName", "t")]),
    "GetModuleHandle": ("load", [("lpModuleName", "t")]),
    "RegOpenKeyEx": ("antivm", [("hKey", "x"), ("lpSubKey", "t"), ("ulOptions", "x"), ("samDesired", "x")]),
    "RegQueryValueEx": ("antivm", [("hKey", "x"), ("lpValueName", "t"), ("lpReserved", "x"), ("lpType", "x"), ("lpData", "x"), ("lpcbData", "x")]),
    "GetFileAttributes": ("antivm", [("lpFileName", "t")]),
    "GetDiskFreeSpaceEx": ("antivm", [("lpDirectoryName", "t")]),
    "FindWindow": ("antivm", [("lpClassName", "t"), ("lpWindowName", "t")]),
    "GetComputerName": ("discover", [("lpBuffer", "x"), ("nSize", "x")]),
    "GetUserName": ("discover", [("lpBuffer", "x"), ("pcbBuffer", "x")]),
    "RegSetValueEx": ("persist", [("hKey", "x"), ("lpValueName", "t"), ("Reserved", "x"), ("dwType", "x"), ("lpData", "x"), ("cbData", "x")]),
    "RegCreateKeyEx": ("persist", [("hKey", "x"), ("lpSubKey", "t"), ("Reserved", "x"), ("lpClass", "t"), ("dwOptions", "x"), ("samDesired", "x"), ("lpSecurityAttributes", "x"), ("phkResult", "x"), ("lpdwDisposition", "x")]),
    "CreateService": ("persist", [("hSCManager", "x"), ("lpServiceName", "t"), ("lpDisplayName", "t")]),
    "CreateMutex": ("discover", [("lpMutexAttributes", "x"), ("bInitialOwner", "x"), ("lpName", "t")]),
    "OpenMutex": ("discover", [("dwDesiredAccess", "x"), ("bInheritHandle", "x"), ("lpName", "t")]),
    "CreateFile": ("file", [("lpFileName", "t"), ("dwDesiredAccess", "x"), ("dwShareMode", "x"), ("lpSecurityAttributes", "x"), ("dwCreationDisposition", "x"), ("dwFlagsAndAttributes", "x")]),
    "DeleteFile": ("file", [("lpFileName", "t")]),
    "CopyFile": ("file", [("lpExistingFileName", "t"), ("lpNewFileName", "t")]),
    "MoveFileEx": ("file", [("lpExistingFileName", "t"), ("lpNewFileName", "t")]),
    "InternetOpen": ("net", [("lpszAgent", "t")]),
    "InternetConnect": ("net", [("hInternet", "x"), ("lpszServerName", "t"), ("nServerPort", "x")]),
    "InternetOpenUrl": ("net", [("hInternet", "x"), ("lpszUrl", "t"), ("lpszHeaders", "t")]),
    "HttpOpenRequest": ("net", [("hConnect", "x"), ("lpszVerb", "t"), ("lpszObjectName", "t"), ("lpszVersion", "t"), ("lpszReferrer", "t")]),
    "HttpSendRequest": ("net", [("hRequest", "x"), ("lpszHeaders", "t"), ("dwHeadersLength", "x"), ("lpOptional", "x"), ("dwOptionalLength", "x")]),
    "URLDownloadToFile": ("net", [("pCaller", "x"), ("szURL", "t"), ("szFileName", "t")]),
}
for _base, (_tag, _args) in _AW.items():
    for _suf, _k in (("A", "s"), ("W", "w")):
        TRACE[_base + _suf] = (_tag, [(n, _k if kd == "t" else kd) for n, kd in _args])

QUIET = {"GetTickCount", "GetTickCount64", "QueryPerformanceCounter", "QueryPerformanceFrequency"}


# ----------------------------------------------------------------------------
# ENTER actions
# ----------------------------------------------------------------------------
def act_crt(ql, a):
    dump_region(ql, a.get("lpStartAddress"), 0x2000, "crt_start")
    dump_region(ql, a.get("lpParameter"), 0x1000, "crt_param")


def act_ncte(ql, a):
    dump_region(ql, a.get("StartRoutine"), 0x2000, "ncte_start")


def act_rcut(ql, a):
    dump_region(ql, a.get("StartAddress"), 0x2000, "rcut_start")


def act_stc(ql, a):
    ctx = a.get("lpContext")
    if not ctx:
        return
    off = 0xF8 if st.arch64 else 0xB8
    raw = safe_read(ql, ctx + off, ptrsize())
    if len(raw) == ptrsize():
        pc = int.from_bytes(raw, "little")
        rec("hollow", f"    SetThreadContext new entry point = {pc:#x}")


def act_cp(ql, a):
    try:
        if int(a.get("dwCreationFlags") or 0) & 0x4:
            rec("hollow", "    CREATE_SUSPENDED set -> classic hollowing / early-bird precursor")
    except Exception:
        pass


def parse_sockaddr(ql, sa):
    raw = safe_read(ql, sa, 28)
    if len(raw) < 8:
        return "?"
    try:
        fam = struct.unpack_from("<H", raw, 0)[0]
        port = struct.unpack_from(">H", raw, 2)[0]
    except Exception:
        return "?"
    if fam == 2 and len(raw) >= 8:
        return f"{'.'.join(map(str, raw[4:8]))}:{port}"
    if fam == 23 and len(raw) >= 24:
        try:
            return f"[{ipaddress.IPv6Address(raw[8:24])}]:{port}"
        except Exception:
            pass
    return f"family={fam} port={port}"


def act_connect(ql, a):
    target = parse_sockaddr(ql, a.get("name"))
    rec("net", f"    -> {target}")
    if ":" in target and not target.startswith("family"):
        host = target.rsplit(":", 1)[0]
        if host and host not in st.iocs_seen:
            st.iocs_seen.add(host)
            rec("ioc", f"{host}   (connect target)", ioc=host, source="connect")


def act_send(ql, a):
    try:
        ln = min(int(a.get("len") or 0), 128)
        if ln <= 0:
            return
        data = safe_read(ql, a.get("buf"), ln)
        if not data:
            return
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        rec("net", f"    payload[:{len(data)}] hex={data.hex()} ascii={txt!r}")
    except Exception:
        pass


ACT = {
    "WriteProcessMemory": lambda ql, a: dump_region(ql, a.get("lpBuffer"), a.get("nSize"), "wpm"),
    "NtWriteVirtualMemory": lambda ql, a: dump_region(ql, a.get("Buffer"), a.get("NumberOfBytesToWrite"), "ntwvm"),
    "CreateRemoteThread": act_crt,
    "CreateRemoteThreadEx": act_crt,
    "NtCreateThreadEx": act_ncte,
    "RtlCreateUserThread": act_rcut,
    "SetThreadContext": act_stc,
    "CreateProcessA": act_cp,
    "CreateProcessW": act_cp,
    "connect": act_connect,
    "WSAConnect": act_connect,
    "send": act_send,
}


def make_enter(name):
    tag, spec = TRACE[name]
    quiet = name in QUIET

    def hook(ql, address, params):
        try:
            st.counts[name] += 1
            st.tags[tag] += 1
            a = get_args(ql, params, spec)
            if not quiet:
                shown = ", ".join(f"{n}={fmt(ql, a[n], k)}" for n, k in spec)
                rec(tag, f"{name}({shown})", api=name, pc=address)
            fn = ACT.get(name)
            if fn:
                try:
                    fn(ql, a)
                except Exception as e:
                    rec("error", f"{name} action failed: {type(e).__name__}: {e}")
        except Exception as e:
            st.api_errors[name] += 1
            rec("error", f"ENTER hook {name} crashed: {type(e).__name__}: {e}")
        return None

    return hook


# ----------------------------------------------------------------------------
# EXIT hooks
# ----------------------------------------------------------------------------
VM_TOKENS = ("vbox", "vmware", "qemu", "virtio", "prl_", "parallels", "vmci", "hgfs", "vmmouse",
             "vmtools", "vmusb", "vmx", "sbiedll", "cuckoo", "xenservice")
VM_FILES = ("vboxmouse", "vboxguest", "vboxsf", "vboxvideo", "vboxservice", "vboxtray", "vmmouse",
            "vmhgfs", "vmci", "vm3dgl", "vmtools", "qemu-ga")
SANDBOX_DLLS = ("sbiedll", "snxhk", "cmdvrt", "api_log", "dir_watch", "vmcheck", "wpespy", "pstorec", "avghookx")
ANALYSIS_WINDOWS = ("ollydbg", "x64dbg", "x32dbg", "windbg", "wireshark", "procmon",
                    "processhacker", "idawindow", "immunitydebugger", "regmonclass", "filemonclass")
BAD_OUI = {bytes.fromhex(x) for x in ("080027", "0a0027", "000569", "000c29", "001c14", "005056",
                                       "001c42", "00163e", "525400", "00155d")}


def hide(arg, wide, tokens, errval, label):
    def h(ql, _pc, p, r):
        try:
            v = read_str(ql, p.get(arg), wide)
            low = v.lower().replace("/", "\\")
            if v and any(t in low for t in tokens):
                rec("evade", f"{label} probe {v!r} -> hidden (ret {errval:#x})", probe=v)
                st.tags["antivm"] += 1
                return errval
        except Exception:
            pass
        return None
    return h


def x_isdbg(ql, _pc, p, r):
    rec("evade", "IsDebuggerPresent -> 0")
    return 0


def x_crdp(ql, _pc, p, r):
    wint(ql, p.get("pbDebuggerPresent"), 0, 4)
    rec("evade", "CheckRemoteDebuggerPresent -> FALSE")
    return None


def x_ntqip(ql, _pc, p, r):
    cls = p.get("ProcessInformationClass")
    buf = p.get("ProcessInformation")
    if buf is None or cls is None:
        return None
    if cls == 0x07:
        wint(ql, buf, 0)
        rec("evade", "NtQueryInformationProcess(ProcessDebugPort) -> 0")
        return 0
    if cls == 0x1F:
        wint(ql, buf, 1, 4)
        rec("evade", "NtQueryInformationProcess(ProcessDebugFlags) -> 1")
        return 0
    if cls == 0x1E:
        wint(ql, buf, 0)
        rec("evade", "NtQueryInformationProcess(ProcessDebugObjectHandle) -> STATUS_PORT_NOT_SET")
        return 0xC0000353
    return None


def x_tick(ql, _pc, p, r):
    st.tick += 1
    return st.tick & 0xFFFFFFFF


def x_tick64(ql, _pc, p, r):
    st.tick += 1
    return st.tick


def x_qpc(ql, _pc, p, r):
    st.tick += 1
    wint(ql, p.get("lpPerformanceCount"), st.tick * 10_000, 8)
    return 1


def x_qpf(ql, _pc, p, r):
    wint(ql, p.get("lpFrequency"), 10_000_000, 8)
    return 1


def x_sysinfo(ql, _pc, p, r):
    si = p.get("lpSystemInfo")
    if si:
        wint(ql, si + (0x20 if st.arch64 else 0x14), 4, 4)
        rec("evade", "GetSystemInfo -> 4 processors")
    return None


def x_cursor(ql, _pc, p, r):
    pt = p.get("lpPoint")
    if pt:
        x, y = 200 + (st.tick * 7) % 900, 150 + (st.tick * 13) % 500
        try:
            safe_write(ql, pt, struct.pack("<ii", x, y))
        except Exception:
            pass
    return None


def x_adapters(ql, _pc, p, r):
    if r != 0:
        return None
    node = p.get("pAdapterInfo")
    psz = ptrsize()
    desc_off, mac_off = (272, 408) if st.arch64 else (268, 404)
    for _ in range(16):
        if not node:
            break
        try:
            mac = safe_read(ql, node + mac_off, 6)
            if len(mac) == 6 and mac[:3] in BAD_OUI:
                safe_write(ql, node + mac_off, b"\x00\x1b\x21" + mac[3:])
                rec("evade", f"adapter MAC {mac.hex(':')} -> VM OUI replaced")
            desc = safe_read(ql, node + desc_off, 132)
            if desc:
                desc_low = desc.split(b"\x00")[0].lower()
                if any(t.encode() in desc_low for t in VM_TOKENS):
                    new = b"Intel(R) 82574L Gigabit Network Connection\x00"
                    safe_write(ql, node + desc_off, new.ljust(132, b"\x00"))
            raw_next = safe_read(ql, node, psz)
            if len(raw_next) != psz:
                break
            node = int.from_bytes(raw_next, "little")
        except Exception:
            break
    return None


def x_valloc(ql, _pc, p, r):
    try:
        prot = int(p.get("flProtect") or 0)
    except Exception:
        prot = 0
    if r and prot & 0xF0:
        tag = "RWX" if prot & 0x40 else "executable"
        size = p.get("dwSize") or 0
        rec("inject", f"    {tag} allocation @ {r:#x} size={int(size):#x} -> watching for first execution")
        watch_exec(ql, r, size, f"VirtualAlloc prot={prot:#x}")
    return None


def x_vprot(ql, _pc, p, r):
    try:
        prot = int(p.get("flNewProtect") or 0)
    except Exception:
        prot = 0
    if r and prot & 0xF0:
        base = p.get("lpAddress")
        size = p.get("dwSize")
        rec("inject", f"    region {int(base or 0):#x} made executable (prot={prot:#x}) -> watching")
        watch_exec(ql, base, size, f"VirtualProtect prot={prot:#x}")
    return None


# --- v4 addition: EXIT-argument logging for high-value APIs ---
def x_createfile(ql, _pc, p, r):
    name = read_str(ql, p.get("lpFileName"), "W" in getattr(r, "_name", "") or False) if False else None
    # Above is dead — we determine wide-ness from the API name in the wrapper below
    return None


def x_regquery(ql, _pc, p, r):
    if r != 0:
        return None
    data_ptr = p.get("lpData")
    cb_ptr = p.get("lpcbData")
    if not data_ptr:
        return None
    cb = 0
    if cb_ptr:
        raw = safe_read(ql, cb_ptr, 4)
        if len(raw) == 4:
            cb = int.from_bytes(raw, "little")
    if cb <= 0 or cb > 0x10000:
        return None
    data = safe_read(ql, data_ptr, cb)
    if not data:
        return None
    # try printable first
    txt = data.split(b"\x00")[0].decode("latin-1", "replace")
    if txt and all(32 <= ord(c) < 127 for c in txt) and len(txt) >= 2:
        rec("antivm", f"    RegQueryValueEx data = {txt!r}")
    else:
        rec("antivm", f"    RegQueryValueEx data hex[:64] = {data[:64].hex()}")
    return None


def x_proc32next(ql, _pc, p, r):
    if r == 0:
        return None
    lppe = p.get("lppe")
    if not lppe:
        return None
    # PROCESSENTRY32.szExeFile is at offset 0x2C (W) / 0x24 (A), 260 chars
    for wide, off in ((True, 0x2C), (False, 0x24)):
        raw = safe_read(ql, lppe + off, 260 * (2 if wide else 1))
        if not raw:
            continue
        name = read_str(ql, lppe + off, wide, 260)
        if name and name.isprintable() and len(name) > 1:
            rec("discover", f"    Process32 -> {name!r}")
            return None
    return None


def x_query_dword_info(ql, _pc, p, r):
    if r != 0:
        return None
    buf = p.get("lpBuffer")
    if buf:
        raw = safe_read(ql, buf, 4)
        if len(raw) == 4:
            rec("antivm", f"    GlobalMemoryStatusEx dwLength read: {int.from_bytes(raw, 'little')}")
    return None


def x_enum_process(ql, _pc, p, r):
    if r == 0:
        return None
    return None


EXIT_HOOKS = {
    "IsDebuggerPresent": x_isdbg,
    "CheckRemoteDebuggerPresent": x_crdp,
    "NtQueryInformationProcess": x_ntqip,
    "GetTickCount": x_tick,
    "GetTickCount64": x_tick64,
    "QueryPerformanceCounter": x_qpc,
    "QueryPerformanceFrequency": x_qpf,
    "GetSystemInfo": x_sysinfo,
    "GetAdaptersInfo": x_adapters,
    "GetCursorPos": x_cursor,
    "VirtualAlloc": x_valloc,
    "VirtualAllocEx": x_valloc,
    "VirtualProtect": x_vprot,
    "VirtualProtectEx": x_vprot,
    "Process32Next": x_proc32next,
    "Process32NextW": x_proc32next,
    "Process32First": x_proc32next,
    "Process32FirstW": x_proc32next,
    "RegQueryValueExA": x_regquery,
    "RegQueryValueExW": x_regquery,
}
for _suf, _wide in (("A", False), ("W", True)):
    EXIT_HOOKS["RegOpenKeyEx" + _suf] = hide("lpSubKey", _wide, VM_TOKENS, 2, "registry")
    EXIT_HOOKS["GetFileAttributes" + _suf] = hide("lpFileName", _wide, VM_FILES, 0xFFFFFFFF, "file")
    EXIT_HOOKS["GetModuleHandle" + _suf] = hide("lpModuleName", _wide, SANDBOX_DLLS, 0, "module")
    EXIT_HOOKS["FindWindow" + _suf] = hide("lpClassName", _wide, ANALYSIS_WINDOWS, 0, "window")


# ----------------------------------------------------------------------------
# CALL hooks (replace implementation)
# ----------------------------------------------------------------------------
def c_sleep(ql, address, params):
    try:
        ms = params.get("dwMilliseconds") if isinstance(params, dict) else None
        if ms is None:
            ms = raw_param(ql, 0)
        ms = int(ms) & 0xFFFFFFFF
    except Exception:
        ms = 0
    st.counts["Sleep"] += 1
    st.tags["timing"] += 1
    if ms == 0xFFFFFFFF:
        rec("timing", "Sleep(INFINITE) -> stopping emulation")
        try:
            ql.emu_stop()
        except Exception:
            pass
        return 0
    st.tick += ms
    st.skipped_ms += ms
    rec("timing", f"Sleep({ms} ms) skipped (total skipped {st.skipped_ms / 1000:.0f}s)")
    return 0


def c_wait(ql, address, params):
    """WaitForSingleObject / WaitForMultipleObjects / NtDelayExecution."""
    name = None
    try:
        # identify by param count / signature
        if isinstance(params, dict):
            if "hHandle" in params:
                name = "WaitForSingleObject"
                timeout = params.get("dwMilliseconds")
            elif "pHandles" in params:
                name = "WaitForMultipleObjects"
                timeout = params.get("dwMilliseconds")
            elif "DelayInterval" in params:
                name = "NtDelayExecution"
                # LARGE_INTEGER, negative = relative, 100-ns units
                raw = safe_read(ql, params.get("DelayInterval"), 8)
                if len(raw) == 8:
                    iv = struct.unpack("<q", raw)[0]
                    timeout = max(0, -iv // 10_000) if iv < 0 else 0
                else:
                    timeout = 0
            else:
                timeout = 0
    except Exception:
        timeout = 0
    try:
        ms = int(timeout or 0) & 0xFFFFFFFF
    except Exception:
        ms = 0
    if ms and ms != 0xFFFFFFFF:
        st.tick += ms
        st.skipped_ms += ms
        st.tags["wait"] += 1
        st.tags["timing"] += 1
        rec("wait", f"{name or 'wait'}({ms} ms) skipped (total {st.skipped_ms / 1000:.0f}s)")
    return 0


CALL_HOOKS = {
    "Sleep": c_sleep,
    "SleepEx": c_sleep,
    "WaitForSingleObject": c_wait,
    "WaitForMultipleObjects": c_wait,
    "WaitForMultipleObjectsEx": c_wait,
    "NtDelayExecution": c_wait,
    "ZwDelayExecution": c_wait,
}


def stub_api(ql, name, retval=0):
    """Register a no-op CALL handler for a broken/missing API."""
    try:
        def _stub(q, addr, params):
            st.counts[name] += 1
            rec("stub", f"{name} -> stubbed ret={retval:#x}", api=name)
            return retval
        ql.os.set_api(name, _stub, CALL)
        return True
    except Exception:
        return False


def install(ql):
    ok = bad = 0

    def reg(name, fn, kind):
        nonlocal ok, bad
        try:
            ql.os.set_api(name, fn, kind)
            ok += 1
        except Exception as e:
            bad += 1
            rec("setup", f"set_api({name}) failed: {type(e).__name__}: {e}")

    for name in TRACE:
        reg(name, make_enter(name), ENTER)
    for name, fn in EXIT_HOOKS.items():
        reg(name, fn, EXIT)
    for name, fn in CALL_HOOKS.items():
        reg(name, fn, CALL)
    rec("setup", f"{ok} hooks installed, {bad} failed")

    # Known-broken APIs in Qiling 1.4.6 — pre-stub them so the sample doesn't die
    for broken in ("GetAdaptersInfo", "GetAdaptersAddresses", "GlobalMemoryStatusEx",
                   "GetSystemInfo", "GetNativeSystemInfo", "NtQuerySystemInformation",
                   "NetUserGetInfo", "NetShareEnum", "WNetOpenEnumW"):
        stub_api(ql, broken, 0)


# ----------------------------------------------------------------------------
# Final sweep / report
# ----------------------------------------------------------------------------
def final_sweep(ql, sample):
    try:
        for ent in ql.mem.get_mapinfo():
            try:
                start, end, perms, label = ent[0], ent[1], ent[2], str(ent[3]).lower()
            except Exception:
                continue
            executable = ("x" in perms) if isinstance(perms, str) else bool(perms & 4)
            if not executable or label.endswith((".dll", ".exe", ".sys", ".drv")):
                continue
            rec("sweep", f"executable non-image region {start:#x}-{end:#x} perms={perms} label={label!r}")
            dump_region(ql, start, end - start, "sweep")
    except Exception as e:
        rec("error", f"final sweep failed: {type(e).__name__}: {e}")
    try:
        name = os.path.basename(sample).lower()
        for img in ql.loader.images:
            try:
                if os.path.basename(img.path).lower() == name:
                    dump_region(ql, img.base, img.end - img.base, "image_final", limit=0x4000000)
            except Exception:
                continue
    except Exception as e:
        rec("error", f"main image dump failed: {type(e).__name__}: {e}")


def hash_file(path):
    out = {}
    for algo in ("md5", "sha1", "sha256"):
        try:
            h = hashlib.new(algo)
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            out[algo] = h.hexdigest()
        except Exception:
            out[algo] = ""
    return out


def write_summary(sample, exit_reason):
    summary = {
        "tool": TOOL_VERSION,
        "sample": os.path.basename(sample),
        "sample_hashes": st.sample_hashes,
        "rootfs": st.rootfs,
        "arch": "x64" if st.arch64 else "x86",
        "end": exit_reason,
        "elapsed_s": round(time.time() - st.t0, 2),
        "sleep_skipped_s": st.skipped_ms // 1000,
        "peb_patched": st.peb_patched,
        "events_written": st.events_written,
        "api_counts": dict(st.counts.most_common()),
        "api_errors": dict(st.api_errors),
        "behaviour_tags": dict(st.tags),
        "attack_hints": {t: ATTACK[t] for t in st.tags if t in ATTACK},
        "iocs": sorted(st.iocs_seen),
        "yara_hits": st.yara_hits,
        "dumps": list(st.dumped.values()),
        "dump_index": st.dump_index,
    }
    path = os.path.join(st.workdir, "summary.json")
    try:
        with open(path, "w") as f:
            json.dump(summary, f, indent=2)
    except Exception as e:
        rec("error", f"failed to write summary.json: {e}")
    rec("summary", f"tags={dict(st.tags)} dumps={len(st.dumped)} -> summary.json")
    return summary


def write_report_md(sample, summary):
    """Markdown triage report."""
    lines = []
    lines.append(f"# Malware Triage Report — `{os.path.basename(sample)}`\n")
    lines.append(f"**Tool:** {TOOL_VERSION}  ")
    lines.append(f"**Emulation:** {'x64' if st.arch64 else 'x86'} Windows via Qiling  ")
    lines.append(f"**Rootfs:** `{st.rootfs}`  ")
    lines.append(f"**Elapsed:** {summary['elapsed_s']} s  ")
    lines.append(f"**Emulation end:** `{summary['end']}`  ")
    lines.append(f"**PEB patched:** {summary['peb_patched']}  ")
    lines.append(f"**Sleep skipped:** {summary['sleep_skipped_s']} s\n")

    lines.append("## Sample hashes\n")
    lines.append("| algo | hash |")
    lines.append("|---|---|")
    for algo, h in (st.sample_hashes or {}).items():
        lines.append(f"| {algo} | `{h}` |")
    lines.append("")

    lines.append("## ATT&CK technique hints\n")
    if summary["attack_hints"]:
        lines.append("| tag | technique | count |")
        lines.append("|---|---|---|")
        for tag, tech in summary["attack_hints"].items():
            lines.append(f"| {tag} | {tech} | {summary['behaviour_tags'].get(tag, 0)} |")
    else:
        lines.append("_none_")
    lines.append("")

    lines.append("## IOCs\n")
    if summary["iocs"]:
        for i in summary["iocs"][:500]:
            lines.append(f"- `{i}`")
    else:
        lines.append("_none_")
    lines.append("")

    lines.append("## YARA hits\n")
    if summary["yara_hits"]:
        for y in summary["yara_hits"]:
            lines.append(f"- `{y}`")
    else:
        lines.append("_none_")
    lines.append("")

    lines.append("## Dumps\n")
    if summary["dump_index"]:
        lines.append("| tag | addr | size | PE | sha256 | path |")
        lines.append("|---|---|---|---|---|---|")
        for d in summary["dump_index"]:
            lines.append(f"| {d['tag']} | {d['addr']:#x} | {d['size']} | {d['pe']} | `{d['sha256'][:16]}…` | `{d['path']}` |")
    else:
        lines.append("_none_")
    lines.append("")

    lines.append("## Top API calls\n")
    lines.append("| API | count |")
    lines.append("|---|---|")
    for api, n in list(summary["api_counts"].items())[:60]:
        lines.append(f"| `{api}` | {n} |")
    lines.append("")

    lines.append("## Timeline (first 500 events)\n")
    lines.append("```")
    for ev in st.timeline[:500]:
        lines.append(f"[{ev['t']:9.3f}] [{ev['kind']}] {ev['msg']}")
    if len(st.timeline) > 500:
        lines.append(f"... ({len(st.timeline) - 500} more events in events.jsonl)")
    lines.append("```")

    path = os.path.join(st.workdir, "report.md")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        rec("report", f"markdown report -> report.md ({len(lines)} lines)")
    except Exception as e:
        rec("error", f"failed to write report.md: {e}")


def write_manifest(sample):
    manifest = {
        "tool": TOOL_VERSION,
        "sample": os.path.basename(sample),
        "sample_hashes": st.sample_hashes,
        "rootfs": st.rootfs,
        "arch": "x64" if st.arch64 else "x86",
        "started": st.t0,
        "finished": time.time(),
        "files": [],
    }
    for root, _dirs, files in os.walk(st.workdir):
        for fn in files:
            full = os.path.join(root, fn)
            try:
                sz = os.path.getsize(full)
            except Exception:
                sz = -1
            manifest["files"].append({
                "path": os.path.relpath(full, st.workdir),
                "size": sz,
                "sha256": hash_file(full).get("sha256", ""),
            })
    try:
        with open(os.path.join(st.workdir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)
    except Exception as e:
        rec("error", f"failed to write manifest.json: {e}")


def make_zip():
    try:
        with zipfile.ZipFile(st.zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _dirs, files in os.walk(st.workdir):
                for fn in files:
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, st.workdir)
                    z.write(full, rel)
        return st.zip_path
    except Exception as e:
        rec("error", f"zip failed: {type(e).__name__}: {e}")
        return None


def load_yara(rules_arg):
    if not rules_arg:
        return None
    if not HAVE_YARA:
        print("[!] yara-python not installed; --yara-rules ignored")
        return None
    try:
        if os.path.isdir(rules_arg):
            filepaths = {}
            for fn in os.listdir(rules_arg):
                if fn.lower().endswith((".yar", ".yara")):
                    filepaths[fn] = os.path.join(rules_arg, fn)
            if not filepaths:
                return None
            return yara.compile(filepaths=filepaths)
        return yara.compile(filepath=rules_arg)
    except Exception as e:
        print(f"[!] yara compile failed: {e}")
        return None


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Qiling PE malware intel collector (v5)")
    ap.add_argument("--rootfs", default="/opt/qiling/rootfs/x8664_windows")
    ap.add_argument("--out", default="qiling_out.zip")
    ap.add_argument("--timeout", type=float, default=0)
    ap.add_argument("--max-insn", type=int, default=0)
    ap.add_argument("--verbose", choices=["off", "default", "debug", "disasm"], default="default")
    ap.add_argument("--yara-rules", default=None, help="YARA rule file or directory")
    ap.add_argument("--no-peb-patch", action="store_true", help="skip PEB patching")
    ap.add_argument("--keep-temp", action="store_true", help="keep staging directory")
    ap.add_argument("sample")
    ap.add_argument("sample_args", nargs=argparse.REMAINDER)
    a = ap.parse_args()

    _arch, a.rootfs = check_sample_arch(a.sample, a.rootfs)

    sample_abs = os.path.abspath(a.sample)
    rootfs_abs = os.path.abspath(a.rootfs)
    if not sample_abs.startswith(rootfs_abs + os.sep):
        # Qiling's windows loader maps the exe path relative to the rootfs
        # (GetModuleFileName etc.) and crashes if the sample lives outside it,
        # so stage a copy inside the arch rootfs dir like qiling's own examples.
        dest = os.path.join(rootfs_abs, os.path.basename(sample_abs))
        shutil.copy2(sample_abs, dest)
        print(f"[+] sample staged inside rootfs: {dest}")
        a.sample = dest

    if not HAVE_QILING:
        print(f"[!] Failed to import qiling: {QILING_IMPORT_ERROR}")
        print("    Install with:  pip install qiling==1.4.6")
        sys.exit(1)

    st.zip_path = os.path.abspath(a.out)
    st.workdir = tempfile.mkdtemp(prefix="qiling_harness_")
    os.makedirs(os.path.join(st.workdir, "dumps"), exist_ok=True)
    st.log = open(os.path.join(st.workdir, "trace.log"), "w", buffering=1)
    st.jsonl = open(os.path.join(st.workdir, "events.jsonl"), "w", buffering=1)
    st.t0 = time.time()
    st.rootfs = a.rootfs
    st.sample_path = os.path.abspath(a.sample)
    st.verbose = a.verbose
    st.sample_hashes = hash_file(st.sample_path)
    st.yara_rules = load_yara(a.yara_rules)

    verbose = {"off": QL_VERBOSE.OFF, "default": QL_VERBOSE.DEFAULT,
               "debug": QL_VERBOSE.DEBUG, "disasm": QL_VERBOSE.DISASM}[a.verbose]

    reason = "completed"
    ql = None
    try:
        ql = Qiling([a.sample] + a.sample_args, a.rootfs, verbose=verbose)
        st.arch64 = ql.arch.bits == 64

        install(ql)
        if not a.no_peb_patch:
            try:
                patch_peb(ql)
            except Exception as e:
                rec("error", f"PEB patch failed: {type(e).__name__}: {e}")

        rec("start", f"{a.sample} {a.sample_args} | rootfs={a.rootfs} | {'x64' if st.arch64 else 'x86'}")
        if st.sample_hashes.get("sha256"):
            rec("start", f"sample sha256={st.sample_hashes['sha256']}")

        try:
            ql.run(timeout=int(a.timeout * 1_000_000) if a.timeout else 0,
                   count=a.max_insn if a.max_insn else 0)
        except KeyboardInterrupt:
            reason = "interrupted"
        except Exception as e:
            reason = f"{type(e).__name__}: {e}"
            rec("end", f"emulation terminated: {reason}")
            tb = traceback.format_exc()
            try:
                with open(os.path.join(st.workdir, "traceback.txt"), "w") as f:
                    f.write(tb)
            except Exception:
                pass

        try:
            final_sweep(ql, a.sample)
        except Exception as e:
            rec("error", f"final_sweep crashed: {type(e).__name__}: {e}")

    except Exception as e:
        reason = f"startup: {type(e).__name__}: {e}"
        rec("fatal", reason)
        try:
            with open(os.path.join(st.workdir, "traceback.txt"), "w") as f:
                f.write(traceback.format_exc())
        except Exception:
            pass

    finally:
        try:
            summary = write_summary(a.sample, reason)
            write_report_md(a.sample, summary)
        except Exception as e:
            rec("error", f"summary/report failed: {type(e).__name__}: {e}")
        try:
            if st.log:
                st.log.close()
            if st.jsonl:
                st.jsonl.close()
        except Exception:
            pass
        try:
            write_manifest(a.sample)
        except Exception:
            pass
        z = make_zip()
        if z:
            print(f"\n[+] results written to {z}")
            if not a.keep_temp:
                try:
                    shutil.rmtree(st.workdir, ignore_errors=True)
                except Exception:
                    pass
        else:
            print(f"\n[!] zip failed; staging dir kept at {st.workdir}")


if __name__ == "__main__":
    main()