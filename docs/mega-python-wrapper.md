# MEGA Python wrapper

`mega/` is the Python layer between an evidence bundle on this host and a MEGA
account. It builds deterministic archives, protects them with a password,
uploads and downloads them through the MEGAcmd CLI, verifies what came back, and
creates/revokes public links.

This page is the API and integration reference. It is written for code that
wants to drive the wrapper from a server (for example a STIX bundler that
exports and retrieves artifacts) rather than for someone typing the commands by
hand. The narrative, measured MEGAcmd behaviour and design rationale live in
[`mega/README.md`](../mega/README.md).

---

## Contents

1. [What the wrapper is](#what-the-wrapper-is)
2. [Requirements](#requirements)
3. [How to import it](#how-to-import-it)
4. [Naming and on-disk contract](#naming-and-on-disk-contract)
5. [Module reference](#module-reference)
   - [`megacmd.py`](#megacmdpy--the-only-mega-aware-layer)
   - [`upload.py`](#uploadpy--build-and-export-a-bundle)
   - [`list.py`](#listpy--enumerate-remote-bundles)
   - [`share.py`](#sharepy--public-links)
   - [`recover.py`](#recoverpy--download-and-verify)
   - [`restore.py`](#restorepy--download-verify-and-extract)
   - [`protect.py`](#protectpy--password-protection)
   - [`credential.py`](#credentialpy--sealed-mega-credential)
   - [`login.py`](#loginpy--open-the-credential-and-establish-a-session)
   - [`seal.py`](#sealpy--legacy-only)
6. [Error model and exit codes](#error-model-and-exit-codes)
7. [Building the bundler server](#building-the-bundler-server)
8. [HTTP surface suggested by the modules](#http-surface-suggested-by-the-modules)
9. [Environment variables and locations](#environment-variables-and-locations)
10. [Security rules the wrapper assumes](#security-rules-the-wrapper-assumes)
11. [MEGAcmd behaviour to keep in mind](#megacmd-behaviour-to-keep-in-mind)
12. [Testing](#testing)

---

## What the wrapper is

```
exports/<artifact>_analysis/          (analyzer output, including stix/)
        |
        |  upload.py: collect -> deterministic tar.gz -> .sha256
        |             -> optional AES-256 zip -> manifest.json + README.txt
        v
exports/<artifact>_artifact/          (local bundle)
        |
        |  megacmd.py -> MEGAcmd CLI (put)
        v
<remote_root>/<artifact>_artifact/    (remote bundle)
        |
        |  share.py / megacmd.public_link -> https://mega.nz/folder/...
        v
public link (a capability: the decryption key is in the URL fragment)
```

The reverse path is `list.py` (what exists), `recover.py` (download + verify the
archive digest) and `restore.py` (download + verify + safely extract + verify
every file against `manifest.json`).

The package is deliberately split so there is exactly one place that knows each
thing:

| Module | Single responsibility |
| --- | --- |
| `megacmd.py` | Find and invoke the MEGAcmd CLI, parse its quirks, session, links |
| `upload.py` | Evidence directory → deterministic bundle → upload |
| `list.py` | Parse `ls -l` into bundle records |
| `share.py` | List/create/revoke public links |
| `recover.py` | Download a bundle and re-hash the archive |
| `restore.py` | Download, verify and safely extract a bundle |
| `protect.py` | Password-protect/unprotect the archive (WinZip AES-256) |
| `credential.py` | Seal/open the MEGA account credential (AES-256-GCM) |
| `login.py` | Read the seal and ensure a MEGAcmd session |
| `seal.py` | Legacy X25519 bundle sealing; decrypt-only for old bundles |

### Is there an SDK?

There is **no packaged SDK**: `mega/` has no `__init__.py`, no `setup.py`, no
type stubs, and no single `MegaClient` class. What it does have is a set of
importable modules with plain functions, plus CLI entry points. That is enough
to code against, but you choose the boundary.

Verified on Python 3.14.4 in the project venv: all ten modules import, the CLI
is found (`%LOCALAPPDATA%\MEGAcmd\MEGAclient.exe`), a MEGA session is active,
and the pure functions below run correctly.

The calls you will actually use:

| Task | Call |
| --- | --- |
| Am I logged in? | `megacmd.whoami() -> str \| None` |
| Is the CLI installed? | `megacmd.available() -> bool` |
| List remote bundles | `list.ls(remote_root, timeout) -> list[dict]` |
| Read an existing link | `megacmd.exported_link(remote_path)` |
| Create a link | `megacmd.public_link(remote_path, expire="7d")` |
| Build a deterministic archive | `upload.build_archive(source, archive)` |
| Build + upload in one call | `upload.main()` (CLI), or `build_archive` + `upload_megacmd` |
| Upload an already-built folder | `upload.upload_megacmd(local_dir, remote_root, timeout)` |
| Protect / unprotect | `protect.zip_bundle(...)` / `protect.unzip_bundle(...)` |
| Read the sealed account | `credential.open_sealed(enc, key=...)` |
| Download + verify | `recover.main()` (CLI) |
| Download + verify + extract | `restore.main()` (CLI) or its functions |

Minimum in-process smoke test (no network, no upload):

```python
import sys
sys.path.insert(0, r"C:\Users\The4thReich\Desktop\IAProject\mega")

import megacmd, upload, list as mega_list, share, protect

print(megacmd.available(), megacmd.whoami())          # CLI + session
rows = mega_list.ls("/", timeout=60)                  # remote bundles
print(share.parse_exports(""))                         # parser is pure
print(protect.password_file())                         # where the zip password lives
```

Two integration realities to plan around:

- `megacmd.py`, `list.py`, `share.py` and `protect.py` are safe to call
  in-process for short operations.
- `upload.py` and `restore.py` are long-running, print narration, and depend on
  the process staying alive; run them as subprocess **jobs** and poll their
  exit code. That is how the admin panel does it.

If you want a real SDK surface (`MegaClient.export()`, `.list()`,
`.link()`, `.retrieve()`), it does not exist yet; the recipes in
[Building the bundler server](#building-the-bundler-server) are the pieces to
wrap. Adding `mega/sdk.py` as a thin facade is a small, contained change if you
want that before starting.

---

## Requirements

| Requirement | Needed by | Notes |
| --- | --- | --- |
| Python 3.9+ | everything | the repo's venv and `python.exe` are newer |
| MEGAcmd CLI | `megacmd`, `upload`, `list`, `share`, `recover`, `restore` | Windows: `MEGAclient.exe` + `mega-*.bat`; POSIX: `megacmd` |
| `cryptography` | `credential.py`, `seal.py` | AES-GCM, scrypt, X25519 |
| `pyzipper` | `protect.py` | only when password protection is enabled |
| `gpg` | legacy GPG seal only | optional |

The archive/verification half of `upload.py` works without MEGAcmd: it returns
exit `3` after writing a complete, verified local bundle. That matters for a
server, because "the bundle was built but the cloud is unavailable" is a
recoverable state, not a lost run.

The modules use only the standard library otherwise, which is why `list.py`,
`share.py` and `recover.py` can be loaded in the panel's process without pulling
in the analyzer.

---

## How to import it

`mega/` is a directory of scripts, not an installed package (there is no
`__init__.py`). You have two supported integration styles.

### 1. Subprocess (recommended for a server boundary)

This is what the admin panel does for export and recovery. It keeps MEGAcmd
failures, timeouts and partial output out of the server process, and it keeps
the wrapper's optional dependencies (`pyzipper`, `cryptography`) out of the
server's import graph.

```python
import json
import subprocess
import sys
from pathlib import Path

MEGA_DIR = Path("C:/Users/The4thReich/Desktop/IAProject/mega")

def mega(module: str, *args: str, timeout: float = 3600) -> subprocess.CompletedProcess:
    """Run one mega/ script with an argument list (never a shell string)."""
    return subprocess.run(
        [sys.executable, str(MEGA_DIR / module), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout,
    )

# Machine-readable calls have --json:
out = mega("list.py", "--remote-root", "/", "--json")
listing = json.loads(out.stdout)          # only if out.returncode == 0

# Export/recover are jobs: the exit code is the contract, stdout is narration.
job = mega("upload.py", "--artifact", "quick_test",
           "--remote-root", "/Cases/2026-10",
           "--encrypt", "--timeout", "900")
```

### 2. Load by path (recommended for read-only, in-process use)

`list.py` is named `list` (the builtin), and `credential.py` is a very generic
name, so do not put `mega/` on `sys.path` and `import` them naively. Load the
file under a private module name, exactly as
`python/panel/artifacts/artifacts.py::_load_mega()` does.

```python
import importlib.util
import sys
from pathlib import Path

MEGA_DIR = Path("C:/Users/The4thReich/Desktop/IAProject/mega")
if str(MEGA_DIR) not in sys.path:
    sys.path.insert(0, str(MEGA_DIR))       # megacmd is imported top-level by the scripts

def load(name: str):
    module_name = f"mega_{name}"
    spec = importlib.util.spec_from_file_location(module_name, MEGA_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    # Register BEFORE exec_module: megacmd.py defines a module-level @dataclass
    # (Result), and Python 3.13+/3.14 dataclasses look the defining module up in
    # sys.modules. Without this, loading megacmd.py by path raises
    # AttributeError: 'NoneType' object has no attribute '__dict__'.
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

megacmd = load("megacmd")
listing = load("list")
upload  = load("upload")
share   = load("share")

account = megacmd.whoami()
bundles = listing.ls("/", timeout=60)
link    = megacmd.public_link("/quick_test_artifact")
```

Caveats:

- **Register the module in `sys.modules` before `exec_module`.** On Python
  3.14 (verified) `megacmd.py` fails to load by path otherwise, because its
  `Result` dataclass is defined at module level. The helper above does it.
- `list.py`, `upload.py`, `share.py`, `recover.py` and `login.py` all insert
  their own directory into `sys.path` as an import side effect, so `megacmd`
  resolves.
- Loading a module twice creates two module objects. Do not compare exception
  classes across loaders (`except megacmd.MegaError` only catches the instance
  from the same module object).
- Long uploads still block the caller; if you are in a request handler, run them
  in a thread or a subprocess. MEGAcmd calls are I/O-bound and serialised below.

---

## Naming and on-disk contract

These names are load-bearing: `upload.py`, `recover.py`, `restore.py` and the
panel all derive remote paths from them.

| Thing | Name / pattern |
| --- | --- |
| Evidence source | `exports/<artifact>_analysis/` (default for `upload.py`) |
| Local bundle | `<out_root>/<artifact>_artifact/` (default `out_root` = `exports/`) |
| Archive | `<artifact>_evidence.tar.gz` |
| Archive digest | `<artifact>_evidence.tar.gz.sha256` |
| Protected archive | `<artifact>_evidence.zip` (+ `.sha256` when shipped) |
| Machine inventory | `manifest.json` |
| Human summary | `README.txt` |
| Remote bundle | `<remote_root>/<artifact>_artifact/` |
| Recovered tree | `exports/<artifact>_recovered/` (`restore.py --dest` overrides) |

`<artifact>` must be a plain name: `upload.py` and `recover.py` reject an empty
string, `/`, `\` or a leading `.` with exit `2`. A bundler server should apply
the same rule before building a path.

### Bundle contents

```
<artifact>_artifact/
    <artifact>_evidence.tar.gz            deterministic tar + gzip
    <artifact>_evidence.tar.gz.sha256     "<hex>  <filename>\n"
    manifest.json
    README.txt
    <artifact>_evidence.zip               only with --encrypt (local only)
    <artifact>_evidence.zip.sha256        only with --encrypt (the shipped digest)
```

With `--encrypt`, the plaintext archive stays local; only the zip is staged for
upload. The zip's sidecar describes the bytes MEGA received; the archive's own
sidecar and `manifest.archive_sha256` describe the plaintext archive so the
recovered evidence can still be proven.

### `manifest.json`

```json
{
  "artifact": "quick_test",
  "generated_at": "2026-11-03T12:00:00+01:00",
  "generated_at_utc": "2026-11-03T11:00:00+00:00",
  "source": "C:\\...\\exports\\quick_test_analysis",
  "archive": "quick_test_evidence.tar.gz",
  "archive_sha256": "<64 hex>",
  "archive_bytes": 541106,
  "file_count": 26,
  "files": [{"path": "stix/bundle.json", "size": 1234}],
  "tool": "mega/upload.py",
  "encrypted": false,
  "encryption": {
    "algorithm": "AES-256 (WinZip WZ_AES)",
    "format": "password-protected ZIP",
    "sealed_file": "quick_test_evidence.zip",
    "sealed_bytes": 234567,
    "sealed_sha256": "<64 hex>",
    "library": "python-pyzipper"
  }
}
```

`encryption` is present only when protected. The operator password file path is
deliberately **not** recorded, because the manifest itself travels to MEGA.

### Determinism

`build_archive()` sorts members and normalises `uid`, `gid`, `uname`, `gname`,
`mtime`, modes, the gzip header timestamp and the gzip filename field. The same
source therefore produces a byte-identical archive and the same SHA-256.
`upload.py --dry-run` rebuilds and asserts this. If a rebuild differs, the
evidence changed; the tooling did not drift.

### What is never archived

- names: `credentials.gpg`, `credentials.json`, `.env`, `cookies.txt`
- suffixes: `.gpg`, `.key`, `.pem`
- top-level directories: `mega/`, `.git/`, `.venv/`, `node_modules/`,
  `__pycache__/`
- symlinks and non-regular files

This is enforced by `upload._excluded()` and `upload.collect()`, not by how the
directory happens to look.

---

## Module reference

### `megacmd.py` — the only MEGA-aware layer

Everything that shells out to MEGAcmd goes through this module. It locates the
CLI on Windows and POSIX, strips progress redraws, applies a timeout, and
translates non-zero exits into `MegaError`.

```python
DEFAULT_TIMEOUT = 300       # seconds, for a transfer
QUICK_TIMEOUT   = 60        # seconds, for session/listing/export calls
```

| API | Returns | Behaviour |
| --- | --- | --- |
| `client() -> Path \| None` | CLI path | Prefers `MEGAclient.exe`, then `megacmd` |
| `wrapper(command) -> Path \| None` | `mega-<cmd>.bat/.cmd/.exe` | Fallback shim |
| `available() -> bool` | bool | `client()` or a `whoami` shim exists |
| `missing_message() -> str` | install instructions | Safe to show to an operator |
| `run(command, *args, timeout=DEFAULT_TIMEOUT, check=True) -> Result` | `Result` | Raises `MegaError` unless `check=False` |
| `clean(text) -> str` | cleaned text | Removes progress bars and transfer boxes |
| `whoami(timeout=QUICK_TIMEOUT) -> str \| None` | email | `None` when there is no usable session |
| `logged_in(email=None, timeout=QUICK_TIMEOUT) -> bool` | bool | Case-insensitive account check |
| `valid_duration(text) -> bool` | bool | MEGA expiry grammar (`M`=minutes, `m`=months) |
| `link_from(text) -> str \| None` | URL | First `https://mega.nz/folder\|file/...` |
| `exported_link(remote_path, timeout=QUICK_TIMEOUT) -> str \| None` | URL | Read-only; `None` if not exported (exit 53) |
| `public_link(remote_path, timeout=QUICK_TIMEOUT, expire=None) -> str` | URL | Reads an existing link, else creates one (`export -a -f`) |

`Result` is a dataclass:

```python
Result(cmd="ls", argv=[...], code=0, out="...", err="...")
result.text    # out + "\n" + err, both already cleaned
```

`MegaError(RuntimeError)` is raised for a non-zero exit, a timeout, or a CLI
that cannot be started. It never carries secret material. With `check=False` you
get the `Result` and decide for yourself — that is how "not exported" (53) and
"already exists" (54) are treated as answers rather than failures.

```python
# Is anyone logged in, and as whom?
email = megacmd.whoami()
if email is None:
    raise RuntimeError("run: python mega/login.py --mega")

# Read an existing link without publishing anything.
link = megacmd.exported_link("/quick_test_artifact")

# Publish explicitly, with a 7-day expiry.
link = megacmd.public_link("/quick_test_artifact", expire="7d")
```

`public_link()` is idempotent: it reads first, creates only when there is no
link, and returns an existing link unchanged. An expiry applies only at
creation; MEGA cannot modify an export in place. On a free account, requesting
an expiry raises `MegaError` rather than silently creating a permanent link.

### `upload.py` — build and export a bundle

Builds the deterministic archive and, unless told otherwise, uploads it.

```python
class BundleError(RuntimeError)

sha256_file(path: Path, chunk: int = 1 << 20) -> str
collect(source: Path) -> list[tuple[Path, Path]]           # (absolute, relative)
build_archive(source: Path, archive: Path) -> tuple[int, int, int]
                                                           # (files, raw_bytes, archive_bytes)
write_readme(out_dir, artifact, source, archive, digest,
             files, raw_bytes, archive_bytes, encryption=None) -> Path
write_manifest(out_dir, artifact, source, archive, digest,
               members, encryption=None) -> Path
find_megacmd() -> bool
remote_exists(remote_path: str) -> bool
upload_megacmd(local_dir: Path, remote_root: str, timeout: int) -> str
                                                           # remote path that landed
stage_for_upload(out_dir, artifact, shipped, shipped_name,
                 encryption) -> tuple[Path, Path | None]
                                                           # (folder to upload, temp root)
sealed_email() -> str | None                               # expected account, never the password
main() -> int
```

`build_archive()` raises `BundleError` when the source contains nothing that
ships. `upload_megacmd()` runs `mkdir -p` first and then `put`, because `put -c`
flattens when it creates the destination itself. It returns
`<remote_root>/<local_dir.name>`; callers still re-list with `remote_exists()`
because MEGAcmd's success message is not proof of the final shape.

`stage_for_upload()` is the protection boundary: when `encryption` is set it
copies only the shipped zip, its sidecar, `manifest.json` and `README.txt` into
a temporary `<artifact>_artifact/` folder, so a plain `put` cannot sweep the
plaintext archive up with the ciphertext.

#### CLI

```powershell
python mega/upload.py --artifact quick_test --dry-run
python mega/upload.py --artifact quick_test
python mega/upload.py --artifact quick_test --no-upload
python mega/upload.py --artifact quick_test --remote-root /Cases/2026-10
python mega/upload.py --artifact quick_test --expect-account a@b.com
python mega/upload.py --artifact quick_test --encrypt
python mega/upload.py --artifact quick_test --source exports/quick_test_analysis/stix
```

| Flag | Meaning |
| --- | --- |
| `--artifact NAME` | required; bundle is `<NAME>_artifact` |
| `--source DIR` | evidence dir (default `exports/<artifact>_analysis`) |
| `--out-root DIR` | bundle parent (default `exports/`) |
| `--remote-root PATH` | MEGA parent (default `/`); bundle lands at `<PATH>/<artifact>_artifact` |
| `--no-upload` | build and verify only |
| `--dry-run` | also rebuild and prove the digest reproduces |
| `--timeout SECONDS` | MEGAcmd upload timeout (default 300) |
| `--encrypt` / `--no-encrypt` | password-zip the archive, or upload as-is |
| `--password-file PATH` | override the operator password file |
| `--expect-account EMAIL` | refuse to upload under another account (default: sealed credential) |
| `--color auto\|always\|never` | narration colour (default `always`; `NO_COLOR` disables) |

`--recipient` and `--admin-key` are accepted and ignored for compatibility with
an older analyzer; they no longer select a scheme.

#### Exit codes

| Code | Meaning | What a server should do |
| --- | --- | --- |
| `0` | built (and uploaded, if requested) | success |
| `1` | build/upload failed | report the log, keep the local bundle if it exists |
| `2` | bad arguments, or no evidence directory | client error |
| `3` | bundle built, but MEGAcmd unavailable | retry upload later; do not rebuild |
| `4` | protection requested but password/pyzipper missing | nothing was uploaded; fix the password |

### `list.py` — enumerate remote bundles

```python
SUFFIX = "_artifact"

human(n: int) -> str
parse_ls(text: str) -> list[dict]
ls(remote: str, timeout: int) -> list[dict]
guard() -> int | None          # 3 = no MEGAcmd, 2 = no session, None = proceed
main() -> int
```

Each row from `parse_ls()` / `ls()`:

```python
{
    "name": "quick_test_artifact",
    "kind": "d",          # leftmost FLAGS char: d/-/r/i/b/x
    "is_dir": True,
    "size": 0,            # folders report "-"
    "date": "2026-10-13", # or "13Oct2026 15:53:11"
}
```

`ls()` calls `ls -l --time-format=ISO6081`, but the parser tolerates both date
shapes because the installed build ignores the format flag. The node type is the
**leftmost** FLAGS character; reading the last character makes every folder look
like a file.

#### CLI

```powershell
python mega/list.py
python mega/list.py --remote-root /Cases/2026-10
python mega/list.py --details
python mega/list.py --all
python mega/list.py --json
```

`--json` payload:

```json
{
  "remote_root": "/",
  "account": "operator@example.com",
  "bundles": [{"name": "...", "kind": "d", "is_dir": true, "size": 0, "date": "..."}]
}
```

Exit codes: `0` ok, `1` MEGAcmd failed, `2` no usable session, `3` no MEGAcmd.

### `share.py` — public links

```python
NOT_EXPORTED = 53
NOT_EXPORTED_DELETE = 54

configured_expire() -> str | None       # config/share.json -> link_expire
normalise(path: str) -> str | None      # absolute path, rejects ".."
display(path: str) -> str
parse_exports(text: str) -> list[dict]  # {path, kind, mode, link}
guard() -> int | None
list_exports(timeout: int) -> list[dict]
show(path: str, timeout: int) -> str | None        # read-only
create(path: str, timeout: int, expire=None) -> tuple[bool, str]  # (created, link)
revoke(path: str, timeout: int) -> bool            # False = was not exported
main(argv=None) -> int
```

`create()` reuses an existing link and only calls `export -a -f` when there is
none. `revoke()` re-reads the node after `export -d` and raises if a link is
still there, so a success message is not taken on faith.

The link is a capability: the folder decryption key is in the URL fragment.
Listing (`list_exports`, `show`) never publishes anything. Only `create()` /
`megacmd.public_link()` do. A protected bundle still needs its zip password; an
unprotected bundle is exactly as exposed as its link.

#### CLI

```powershell
python mega/share.py                                # every current export
python mega/share.py --remote-root /Cases/2026-10
python mega/share.py /quick_test_artifact           # read-only
python mega/share.py --create /quick_test_artifact
python mega/share.py --create --expire 7d /quick_test_artifact
python mega/share.py --create --permanent /quick_test_artifact
python mega/share.py --delete /quick_test_artifact
python mega/share.py --json
```

`--expire` uses MEGA's grammar: `s` seconds, `M` minutes, `h` hours, `d` days,
`m` months, `y` years, combinable (`12h`, `1m12d3h`). Case matters. With neither
`--expire` nor `--permanent`, `--create` uses `config/share.json`'s
`link_expire`; an unreadable/invalid value returns `2` instead of quietly
creating a permanent link.

Exit codes: `0` ok, `1` MEGAcmd failed, `2` no session or bad arguments, `3` no
MEGAcmd, `4` the node is not exported (nothing to show or revoke).

### `recover.py` — download and verify

```python
sha256_file(path: Path, chunk: int = 1 << 20) -> str
read_sidecar(bundle: Path, archive: Path) -> str | None
main() -> int
```

It probes `ls`, creates the local destination root, runs `get` **without `-m`**
so the bundle nests, then re-hashes `*_evidence.tar.gz` and compares it with the
sidecar and `manifest.archive_sha256`. If MEGAcmd wrote a sibling (`... (1)`)
because the destination differed, it verifies whichever copy was written most
recently.

```powershell
python mega/recover.py --artifact quick_test
python mega/recover.py --artifact quick_test --remote-root /Cases/2026-10
python mega/recover.py --artifact quick_test --out-root recovered
python mega/recover.py --artifact quick_test --force
```

| Code | Meaning |
| --- | --- |
| `0` | downloaded and digest verified |
| `1` | MEGAcmd failed, or no archive arrived |
| `2` | no session, bad name, or local copy exists without `--force` |
| `3` | no MEGAcmd |
| `4` | **checksum mismatch** — do not trust the copy |
| `5` | nothing at that remote path |

`recover.py` only verifies the archive. For a server that needs the evidence
tree on disk, prefer `restore.py`.

### `restore.py` — download, verify and extract

The full retrieval path, in a fixed order:

1. fetch the bundle into a staging directory;
2. verify `<artifact>_evidence.tar.gz.sha256` **before** opening the tar;
3. inspect every tar member (regular files only, bounded sizes, no escapes)
   before extracting;
4. extract into staging, then check every file against `manifest.json`;
5. only then move the tree to `--dest`.

```python
class RestoreError(RuntimeError)

MAX_MEMBERS = 200_000
MAX_TOTAL_BYTES = 8 * 1024**3
MAX_MEMBER_BYTES = 2 * 1024**3

sha256_file(path, chunk=1 << 20) -> str
parse_digest_file(path, expect_name) -> str
verify_archive_digest(bundle: Path, artifact: str) -> tuple[Path, str]
inspect_members(tar: tarfile.TarFile) -> list[tarfile.TarInfo]
safe_extract(archive: Path, dest: Path) -> int
verify_against_manifest(staging, bundle, artifact) -> tuple[int, list[str]]
default_fetch_cmd() -> str
fetch(artifact, remote_root, dest, fetch_cmd) -> None
list_remote(artifact, remote_root, fetch_cmd) -> int
main() -> int
```

Transport is `mega-download` by default (or `--fetch-cmd` / `$MEGA_FETCH_CMD`),
not `megacmd.get`. On Windows the MEGAcmd install ships the `mega-download.bat`
shim.

```powershell
python mega/restore.py --artifact quick_test
python mega/restore.py --artifact quick_test --dest C:\cases\2026-10
python mega/restore.py --artifact quick_test --list
python mega/restore.py --verify-only --bundle exports\quick_test_artifact
```

`--dest` is replaced if it exists. Without `--dest` the tree goes to
`exports/<artifact>_recovered/`. `--list` returns the transport command's exit
code. A missing `manifest.json` is tolerated (with fewer checks); a missing
sidecar, a digest mismatch, an unsafe tar member or a size mismatch is a
failure.

### `protect.py` — password protection

Wraps the deterministic archive in a one-member WinZip AES-256 zip
(`WZ_AES`, via `pyzipper`). The password lives outside the repo.

```python
class PasswordError(RuntimeError)

password_file(override=None) -> Path
password_present(pfile=None) -> bool
read_password(pfile=None) -> bytes
set_password(value: str | bytes, pfile=None) -> Path
generate_password(length=24, pfile=None) -> tuple[str, Path]
clear_password(pfile=None) -> bool
zip_bundle(archive: Path, out_zip: Path, password: bytes) -> dict
unzip_bundle(zip_path: Path, out_dir: Path, password: bytes) -> Path
get_password_from_cli(args) -> bytes
main() -> int
```

Password file resolution:

1. an explicit path;
2. `IA_BUNDLE_PASSWORD_FILE`;
3. `<credential.secrets_dir()>/bundle-keys/upload.password`.

With the default secrets directory that is
`%APPDATA%\IAProject\mega-secrets\bundle-keys\upload.password`. (The module
docstring and older docs say `%APPDATA%\IAProject\bundle-keys\...`; the code
above is the current definition. Always call `password_file()` rather than
reconstructing it.)

Rules enforced by the API:

- minimum 8 bytes for an operator password; generated passwords are 12–128;
- exactly one trailing `\n` or `\r\n` is stripped on read, every other byte is
  significant;
- `zip_bundle` fixes the entry timestamp to `1980-01-01`, but the random AES
  salt makes the zip bytes differ per run — so the zip's sidecar describes the
  zip, while `manifest.archive_sha256` remains the stable evidence digest;
- a wrong password, truncated zip or altered member fails closed (HMAC +
  password-verification value);
- `clear_password()` is irreversible; a lost password means a lost bundle.

```powershell
python mega/protect.py status
python mega/protect.py zip quick_test_evidence.tar.gz --out quick_custom.zip
python mega/protect.py unzip quick_test_evidence.zip --out-dir .
```

Exit codes from the CLI: `0` ok, `1` `PasswordError`, `2` `pyzipper` missing.

### `credential.py` — sealed MEGA credential

AES-256-GCM over the account JSON, with two key modes:

| Mode | How the key is held | Trade-off |
| --- | --- | --- |
| keyfile (`MODE_KEYFILE=1`) | 32 raw bytes in `credential.key` | no typing; key sits beside the ciphertext |
| scrypt (`MODE_SCRYPT=2`) | passphrase → scrypt(N=2^15, r=8, p=1) | no key file; losing the passphrase loses the credential |

```python
class SealError(RuntimeError)

MAGIC = b"MEGACRED"; VERSION = 1
MODE_KEYFILE = 1; MODE_SCRYPT = 2
HEADER_LEN = 40; KEY_LEN = 32

secrets_dir() -> Path
DEFAULT_ENC  # <secrets>/credentials.enc
DEFAULT_KEY  # <secrets>/credential.key

read_key_file(path) -> bytes
write_key_file(path, key) -> str
harden_file(path) -> str
derive_key(passphrase, salt) -> bytes
seal(payload: dict, enc_path, *, key=None, passphrase=None) -> Path
open_sealed(enc_path, *, key=None, passphrase=None) -> dict
relocate(repo_dir, dest_dir=None) -> int
main() -> int
```

`seal()` requires exactly one of `key` / `passphrase`; the header is bound as
GCM additional data, so a modified mode/version byte fails authentication. The
plaintext JSON must contain `email` and `password`; `app_key`, `root_node` and
`api_url` are optional (`login.parse_credentials` rejects anything else).

File layout (detectable truncation and bad magic):

```
0   8   magic "MEGACRED"
8   1   format version
9   1   key mode (1=keyfile, 2=scrypt)
10  1   reserved, must be 0
11  1   scrypt log2(N)
12  16  scrypt salt (zeroed in keyfile mode)
28  12  GCM nonce
40  ..  ciphertext || 16-byte tag
```

Default location: `%APPDATA%\IAProject\mega-secrets\`, deliberately outside the
repository. Override with `MEGA_SECRETS_DIR`, **set before the module is
imported**: `DEFAULT_ENC` and `DEFAULT_KEY` are computed once at import time
(`protect.password_file()` and `credential.secrets_dir()` are evaluated per
call). If your server changes the environment at runtime, pass explicit paths.
Files are created with mode
`0600`; on Windows `icacls /inheritance:r /grant:r <user>:F` removes inherited
ACEs.

```powershell
python mega/credential.py seal --from cred.json
python mega/credential.py check
python mega/credential.py open
python mega/credential.py relocate
```

### `login.py` — open the credential and establish a session

```python
class LoginError(RuntimeError)

REQUIRED = ("email", "password")
OPTIONAL = ("app_key", "root_node", "api_url")

open_aes(enc, keyf, passphrase) -> dict
open_gpg(seal, passphrase, passphrase_fd) -> dict       # legacy
parse_credentials(data: dict) -> dict
ensure_mega_session(creds, allow_password, auth_code, timeout) -> int
main() -> int
```

`ensure_mega_session()` checks `whoami` **first**; MEGAcmd persists its session,
so a machine already signed in never reads the password. Only when there is no
session does it call `login`, and it requires `--allow-password` because
MEGAcmd accepts the password only as an argv element (visible in the process
list). MFA comes from `MEGA_AUTH_CODE`. After login it checks `whoami` again;
"login succeeded but no session" is a failure.

```powershell
python mega/login.py --emit check          # validate only
python mega/login.py --emit json           # {"email": ..., "password": ...}
python mega/login.py --emit env            # EMAIL=... / PASSWORD=...
python mega/login.py --emit check --mega   # also ensure a session
python mega/login.py --emit check --mega --allow-password
```

The plaintext credential is only ever in memory and on stdout; it is never
written to disk.

Exit codes: `0` ok, `1` session/login failed or wrong account, `2` credential
could not be opened / no session and no `--allow-password`, `3` no MEGAcmd.

### `seal.py` — legacy only

The old X25519 + HKDF-SHA256 + AES-256-GCM bundle envelope (`IABUNDLE`). It
still decrypts bundles produced by older checkouts, but nothing in the current
pipeline produces `.enc` bundles any more; `protect.py` replaced it because
every consumer would otherwise need the private key.

```powershell
python mega/seal.py keygen user
python mega/seal.py encrypt <bundle> --recipient user
python mega/seal.py decrypt <bundle>.enc
python mega/seal.py whoami
python mega/seal.py inspect <bundle>.enc
```

Do not build new export paths on this module.

---

## Error model and exit codes

### Exceptions

| Exception | Raised by | Meaning |
| --- | --- | --- |
| `megacmd.MegaError` | `megacmd.run` and helpers | CLI missing, non-zero exit, or timeout |
| `upload.BundleError` | `upload.py` | nothing to archive, missing staged file |
| `protect.PasswordError` | `protect.py` | no/empty password, pyzipper missing, bad zip |
| `credential.SealError` | `credential.py` | wrong key/passphrase, tampered or malformed seal |
| `login.LoginError` | `login.py` | unreadable credential, bad shape, login failed |
| `restore.RestoreError` | `restore.py` | missing digest, unsafe member, failed fetch |
| `seal.SealError` | `seal.py` | legacy envelope failure |

All of them are `RuntimeError` subclasses. None of them include secret material
in the message; that is a stated invariant of the wrapper.

### Exit-code summary

| Script | Codes |
| --- | --- |
| `upload.py` | `0` ok, `1` failed, `2` arguments/evidence, `3` no MEGAcmd (bundle is fine), `4` protection failed (nothing uploaded) |
| `list.py` | `0` ok, `1` MEGAcmd failed, `2` no session, `3` no MEGAcmd |
| `share.py` | `0` ok, `1` MEGAcmd failed, `2` no session/bad args, `3` no MEGAcmd, `4` not exported |
| `recover.py` | `0` verified, `1` failed/no archive, `2` no session/exists, `3` no MEGAcmd, `4` **checksum mismatch**, `5` not found |
| `restore.py` | `0` ok, `1` any `RestoreError` (including integrity failure) |
| `protect.py` | `0` ok, `1` password error, `2` pyzipper missing |
| `credential.py` | `0` ok, `2` seal/JSON error |
| `login.py` | `0` ok, `1` session failure, `2` credential failure, `3` no MEGAcmd |

Treat `recover.py` code `4` and a `restore.py` integrity failure as *evidence
compromised*: do not extract into a case directory, and do not present the
download as successful.

---

## Building the bundler server

### Export (one artifact)

```python
import subprocess, sys
from pathlib import Path

REPO = Path(r"C:\Users\The4thReich\Desktop\IAProject")
MEGA = REPO / "mega"

def export_artifact(name: str, remote_root: str = "/", encrypt: bool = True,
                    source: Path | None = None, timeout: int = 900) -> dict:
    args = [sys.executable, str(MEGA / "upload.py"),
            "--artifact", name,
            "--remote-root", remote_root,
            "--timeout", str(timeout),
            "--encrypt" if encrypt else "--no-encrypt"]
    if source:
        args += ["--source", str(source)]

    proc = subprocess.run(args, capture_output=True, text=True,
                          encoding="utf-8", errors="replace",
                          timeout=timeout + 180)
    result = {"ok": proc.returncode == 0, "exit": proc.returncode,
              "log": (proc.stdout or "") + (proc.stderr or "")}

    # Exit 3 means the bundle is complete locally but MEGA was unavailable.
    # The caller can retry the upload without rebuilding.
    if proc.returncode == 0:
        result["remote_path"] = f"{remote_root.rstrip('/')}/{name}_artifact"
    return result
```

Then, only when the caller explicitly asked for a link:

```python
# import megacmd by path (see "How to import it") or run share.py --create --json
proc = subprocess.run(
    [sys.executable, str(MEGA / "share.py"), "--create",
     result["remote_path"], "--json"],
    capture_output=True, text=True)
link = json.loads(proc.stdout)["link"]
```

An export should be a **job**, not a blocking request: protecting and uploading
a large bundle takes minutes. The panel's implementation in
`python/panel/artifacts/artifacts.py` is the reference — it streams
`upload.py`'s stdout into an in-memory job record, kills it after
`timeout + 180s`, and invalidates the listing cache on success.

### Retrieve (one artifact)

```python
import subprocess, sys

def retrieve_artifact(name: str, remote_root: str = "/",
                      dest: str | None = None) -> dict:
    args = [sys.executable, str(MEGA / "restore.py"),
            "--artifact", name, "--remote-root", remote_root]
    if dest:
        args += ["--dest", dest]

    proc = subprocess.run(args, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=1800)
    return {"ok": proc.returncode == 0, "exit": proc.returncode,
            "log": (proc.stdout or "") + (proc.stderr or "")}
```

`restore.py` is preferred over `recover.py` when the server must hand back the
evidence tree, because it verifies the digest *before* extracting, rejects
unsafe tar members, and cross-checks every file against `manifest.json`.

If the bundle was protected, the retrieved tree contains the `.zip` rather than
the plaintext archive. Decrypt with `protect.unzip_bundle()` (or
`protect.py unzip`) using the operator password, then extract the `.tar.gz`.

### Listing, links and health

```python
def remote_status(remote_root: str = "/") -> dict:
    # list.py --json is the stable machine contract
    proc = subprocess.run(
        [sys.executable, str(MEGA / "list.py"),
         "--remote-root", remote_root, "--json"],
        capture_output=True, text=True)
    if proc.returncode != 0:
        return {"available": False, "reason": proc.stderr.strip(),
                "bundles": []}
    payload = json.loads(proc.stdout)
    payload["available"] = True
    return payload
```

`--details` only changes the human-readable output; the `--json` payload is
always bundle rows (no per-file listing). For file-level detail, load `list.py`
and call `list.ls(f"{root}/{name}_artifact", timeout)` in-process.

Health check for the server:

```python
# no MEGAcmd -> available() False
# no session -> whoami() is None
# wrong account -> compare with the sealed credential's email
```

`upload.sealed_email()` returns the expected address from the seal without
exposing the password; `megacmd.whoami()` gives the live one. Compare them
before uploading if your server accepts a target account.

### STIX-specific notes

- A run's STIX output is `exports/<artifact>_analysis/stix/` (bundle and
  ATT&CK Navigator layer). If you want a STIX-only artifact, point
  `upload.py --source <...>/stix`; the bundle name still comes from
  `--artifact`.
- Keep the whole analysis directory as the default source when the STIX bundle
  references external files or when retrieved evidence must reproduce the run.
- The archive is deterministic, so a STIX bundle rebuilt from unchanged source
  produces the same SHA-256; this is what makes "the STIX I retrieved is the
  STIX that was exported" provable.
- `<artifact>` is a path component and a remote folder name. Validate it as a
  plain name (`[A-Za-z0-9._-]+`, no leading dot, no separators) before building
  paths; `upload.py` and `recover.py` reject the dangerous cases but your
  router should not rely on that alone.

---

## HTTP surface suggested by the modules

This is a mapping, not an implementation. It matches the capabilities the
wrapper actually has.

| Method + path | Backed by | Notes |
| --- | --- | --- |
| `GET /artifacts?remote_root=/` | `list.py --json` | read-only, never publishes |
| `GET /artifacts/{name}?remote_root=/` | `list.ls()` in-process / `megacmd.exported_link` | 404 if absent; `--details` has no JSON form |
| `POST /artifacts/{name}/export` | `upload.py` as a job | body: `remote_root`, `encrypt`, `timeout`, optional `source` |
| `GET /jobs/{id}` | your job store | state, log lines, exit code, link |
| `POST /artifacts/{name}/recover` | `restore.py` / `recover.py` as a job | 202 + job id; never block the request |
| `POST /artifacts/{name}/link` | `share.py --create` / `megacmd.public_link` | explicit publish; body: `expire` |
| `GET /artifacts/{name}/link` | `share.py <path> --json` / `megacmd.exported_link` | read-only; 404/`exported:false` when none |
| `DELETE /artifacts/{name}/link` | `share.py --delete` / `share.revoke` | idempotent-ish: `4` means it was not exported |
| `GET /health/mega` | `megacmd.available()` + `whoami()` | report CLI missing / no session / account |

Design rules that fall out of the wrapper:

- **Explicit publish only.** Polling/listing must never create a link. A link is
  a bearer capability for the bundle.
- **Uploads and downloads are jobs.** Use a job id + polling; do not hold an
  HTTP request open for a 900-second upload.
- **Exit `3` is not a failed bundle.** Surface "built locally, upload
  unavailable" distinctly from "build failed".
- **Exit `4` from recovery is a security event.** Do not serve the extracted
  tree; report a checksum mismatch.
- **Cache listings deliberately.** MEGAcmd spawns a process per call. The panel
  caches remote listings for five minutes and invalidates on a successful
  export/revoke; a server should do the same.

---

## Environment variables and locations

| Variable | Read by | Effect |
| --- | --- | --- |
| `MEGACMD_HOME` / `MEGAcmd_HOME` | `megacmd._roots` | MEGAcmd install directory |
| `MEGA_SECRETS_DIR` | `credential.secrets_dir` | sealed credential + key location |
| `MEGA_PASSPHRASE` | `login.py` | passphrase for a scrypt-sealed credential |
| `MEGA_GPG_PASSPHRASE` | `login.py` | legacy GPG passphrase (deprecated) |
| `MEGA_AUTH_CODE` | `login.py` | MFA code, kept out of argv |
| `IA_BUNDLE_PASSWORD_FILE` | `protect.password_file` | bundle zip password file |
| `MEGA_FETCH_CMD` | `restore.py` | download command (default `mega-download`) |
| `NO_COLOR` / `FORCE_COLOR` / `TERM` | `upload.py` | narration colour |
| `APPDATA` | `credential.secrets_dir` | Windows profile root |

Config (not environment): `MEGA_UPLOAD`, `MEGA_REMOTE_ROOT`, `MEGA_TIMEOUT`,
`MEGA_SEAL` in `config/analysis.yaml` win over `config/artifacts.yaml`; the
panel and the analyzer apply that precedence. `config/share.json`'s
`link_expire` is the default link expiry.

Locations created by the wrapper:

```
%APPDATA%\IAProject\mega-secrets\
    credentials.enc                 AES-256-GCM ciphertext
    credential.key                  32 raw bytes (keyfile mode only)
    bundle-keys\upload.password     default bundle password file
```

---

## Security rules the wrapper assumes

1. **Never put `mega/` in a bundle.** `upload.py` excludes it, along with
   `.git`, `.venv`, `node_modules`, `__pycache__`, key material and `.env`.
2. **The link is the capability.** `https://mega.nz/folder/...#...` contains the
   folder key. Treat it as a secret unless the bundle is password-protected.
3. **Protection must fail closed.** If `--encrypt` was requested and the
   password file or `pyzipper` is unavailable, `upload.py` returns `4` and
   uploads nothing. Do not add a plaintext fallback in the server.
4. **Only the ciphertext travels when protected.** `stage_for_upload()` exists
   so a folder-level `put` cannot include the plaintext archive.
5. **The wrong account is a hard stop.** `--expect-account` defaults to the
   sealed credential's email. Compare the live `whoami()` before uploading.
6. **The credential never touches disk in plaintext.** `login.py` emits only to
   stdout/memory. Do not log its output.
7. **A password is unrecoverable.** There is no back door in `protect.py`; a
   lost password is a lost bundle by design.
8. **Passwords and credentials are not argv.** The only exception is MEGAcmd
   `login`, which requires `--allow-password` because the CLI offers no other
   channel.

---

## MEGAcmd behaviour to keep in mind

These were measured against a live account and are encoded in the wrapper.
Server code should not "simplify" around them.

1. **`put -c` flattens when it creates the destination.** `upload.py` always
   runs `mkdir -p` first, then `put`, then re-lists. A checksum cannot catch the
   wrong shape because the bytes are identical.
2. **`put <folder> <dest>` nests** as `<dest>/<folder>`. The remote root is the
   *parent* of `<artifact>_artifact`.
3. **`mkdir` is silent on success**, and `mkdir -p` can exit `54` ("already
   exists") for the state you want. The result is arbitrated by a listing.
4. **`get` will not create the destination directory.** It fails with exit `55`
   and "is not a valid Download Folder". `recover.py` creates `out_root` first.
5. **`get -m` merges flat** and drops the wrapper folder, so verification looks
   in the wrong place. Do not pass `-m`.
6. **`get` will not overwrite a differing destination.** It writes a sibling
   with ` (1)`; recovery verifies the most recently written copy.
7. **`ls --time-format` is ignored by some builds.** Dates may be
   `2026-10-13` or `13Oct2026 15:53:11`; parse both.
8. **The node type is the leftmost FLAGS character.** The other three are
   sharing/export status.
9. **`export` says "not exported" with exit `53`** (and `export -d` with `54`).
   Those are answers, not failures.
10. **Only PRO accounts may set a link expiry.** The refusal is surfaced, never
    downgraded to a permanent link.
11. **MEGAcmd persists its session.** `whoami` first; log in only when needed.
12. **Never spawn `MEGAcmdShell.exe`.** It is interactive, takes no command,
    and never exits. `megacmd.py` excludes it on purpose.

---

## Testing

- `mega/test_seal.py` covers the legacy envelope.
- `unit/python/test_artifact_password.py` covers password-file resolution and
  the protect/unprotect round-trip.
- `unit/python/test_password_generator.py` covers the generator bounds.
- The panel's `python/panel/artifacts/artifacts.py` is a working consumer to
  crib from: it loads `list.py` and `megacmd.py` by path, treats every MEGA
  failure as a state (`available: false` + reason), caches listings, and runs
  `upload.py`/`recover.py` as subprocess jobs.

For a new server, the minimum useful test matrix is:

1. list with no MEGAcmd installed → `available: false`, no exception;
2. list with no session → `available: false`, actionable reason;
3. export with `--no-upload` → local bundle with matching sidecar/manifest;
4. export with `--encrypt` and no password file → exit `4`, nothing uploaded;
5. retrieve a tampered archive → checksum mismatch, nothing extracted;
6. retrieve a protected bundle → zip recovered, plaintext absent from MEGA;
7. create → read → revoke a link, and confirm listing never creates one.

---

## See also

- [`mega/README.md`](../mega/README.md) — design rationale and the live-account
  findings behind the gotchas above.
- [`docs/evidence-and-encryption.md`](evidence-and-encryption.md) — where
  generated files live and how protection fits the analyzer.
- [`docs/admin-console/artifacts.md`](admin-console/artifacts.md) — the panel's
  local/remote artifact views, caching and export/recover jobs.
