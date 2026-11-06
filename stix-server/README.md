# `stix-server` MEGA SDK

`mega_client.py` is a single-object facade over this repo's `mega/` scripts, so a
STIX bundler server can export a bundle to MEGA and pull it back again without
shelling out to five different command lines or re-implementing the archive
format.

It does **not** modify `mega/`. It loads those modules by path, calls them
in-process for quick reads, and runs `upload.py` / `restore.py` / `recover.py`
as subprocesses for the long operations.

```
stix-server/
├── mega_client.py   # the SDK: MegaClient, Job, CommandResult, Bundle
├── smoke_test.py    # local + optional read-only remote test
├── README.md        # this file
└── _host_server.py  # your server stub
```

## Quick start

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(r"C:\Users\The4thReich\Desktop\IAProject\stix-server")))
from mega_client import MegaClient

client = MegaClient(remote_root="/evidence")

print(client.status())                 # is MEGAcmd there? logged in? password?
for b in client.list_bundles():        # /evidence/*_artifact
    print(b.artifact, b.remote_path, b.date)

# Build + protect + upload + publish a link, blocking
result = client.export("my_scan", encrypt=True, link=True, expire="7d")
result.require_ok()
print(result.data["remote_path"])      # /evidence/my_scan_artifact
print(result.data["link"])             # https://mega.nz/folder/...

# Download, verify the sha256, safely extract
restored = client.retrieve("my_scan")  # -> exports/my_scan_recovered
restored.require_ok()
```

No `source=` means `upload.py`'s own default: `exports/<name>_analysis`.

## Requirements

| Needs | How to check |
| --- | --- |
| MEGAcmd installed | `client.status()["available"]` |
| A logged-in MEGAcmd session | `client.status()["session_ok"]` |
| Bundle password on disk | `client.status()["password_present"]` |
| Matching MEGA account | `client.status()["account_matches"]` |

If the session is missing:

```powershell
python mega/login.py --emit check --mega
```

The password defaults to
`%APPDATA%\IAProject\mega-secrets\bundle-keys\upload.password` and can be
created with `client.generate_password()` or overridden per call with
`password_file=`.

## Client

```python
MegaClient(
    repo_root=None,        # defaults to IA_REPO_ROOT, then the parent of stix-server
    remote_root="/",       # default MEGA folder for every call
    timeout=300,           # seconds for one upload/recover
    quick_timeout=60,      # seconds for session/listing/link calls
    retrieve_timeout=1800, # subprocess deadline for a full restore
    grace=180,             # extra seconds before a job is killed
    python_executable=None,# defaults to the interpreter running the server
    max_job_lines=4000,    # per-job output ring buffer
)
```

`remote_root` is normalised: backslashes become `/`, `.` and empty segments are
dropped, and `..` is rejected. Every method that takes `remote_root=` overrides
the client default for that one call.

### Status and session

| Method | Returns |
| --- | --- |
| `status()` | dict health snapshot; never raises |
| `account()` | logged-in address or `None` |
| `require_session()` | address, or raises `MegaNotAvailable` / `MegaNotLoggedIn` |
| `module(name)` | raw `mega/<name>.py` module (escape hatch) |
| `megacmd` | the raw `mega/megacmd.py` module |

`status()` keys: `available`, `cli`, `account`, `expected_account`,
`account_matches`, `session_ok`, `remote_root`, `password_file`,
`password_present`, `secrets_dir`, `repo_root`, `error`.

`account_matches` compares the live session against the email sealed in the
credential. `False` means you are about to upload to the wrong account.

### Listing

| Method | Notes |
| --- | --- |
| `bundle_path(name)` | `remote_root/<name>_artifact` |
| `ls(path)` | raw `ls -l` rows: `name`, `kind`, `size`, `date`, `is_dir` |
| `list_bundles(all=False)` | `Bundle` objects; `all=True` includes non-bundle folders |
| `exists(name)` | best-effort, never raises |

`Bundle` fields: `name` (the folder, e.g. `quick_test_artifact`), `artifact`
(the plain name, `quick_test`), `remote_path`, `kind`, `size`, `date`, `is_dir`.
`to_dict()` is JSON-ready.

### Links

| Method | Notes |
| --- | --- |
| `exported_link(name_or_path)` | read an existing link; **never creates one** |
| `link(name_or_path, create=False)` | read, or create with `create=True`; reuses an existing link |
| `revoke_link(name_or_path)` | returns `{"path": ..., "deleted": bool}` |
| `list_links()` | every export, filtered to `remote_root` when it is not `/` |

`link(..., create=True)` expiry rules, identical to `share.py --create`:

* `expire="7d"` — explicit MEGA duration (`12h`, `7d`, `1m12d3h`; `M` = minutes, `m` = months).
* `permanent=True` — no expiry.
* neither — reads `config/share.json`; if that is invalid it raises
  `MegaArgumentError` rather than silently publishing a permanent link.

`name_or_path` accepts a plain artifact name (`quick_test`) or an absolute MEGA
path (`/evidence/quick_test_artifact`). Passing the folder name with the
`_artifact` suffix is rejected with a message telling you to drop it.

### Protection

| Method | Notes |
| --- | --- |
| `password_file()` | path in use (may not exist) |
| `password_present(path=None)` | whether a readable password exists |
| `set_password(value)` | write it byte-exact; minimum 8 bytes |
| `generate_password(length=24)` | returns `(value, path)`; the value is shown once |
| `encrypt_archive(archive, out_zip=None)` | WinZip AES-256 zip; returns the manifest fragment |
| `decrypt_archive(zip_path, out_dir)` | unseal; returns the recovered archive path |

### Export (build + upload)

`export(...)` blocks. `start_export(...)` takes the same keyword arguments and
returns a `Job`.

```python
client.export(
    "my_scan",
    source="exports/my_scan_analysis",  # default: exports/<name>_analysis
    remote_root="/evidence",            # default: the client's
    out_root="exports",                 # default: <repo>/exports
    encrypt=True,                       # default: True
    password_file=None,                 # default: the operator password file
    expect_account=None,                # default: the sealed credential's email
    dry_run=False,                      # also rebuild and prove the digest reproduces
    no_upload=False,                    # build + verify, no network
    link=False, expire=None, permanent=False,
    timeout=None,                       # seconds for the MEGA upload
    color="never",
)
```

`result.data` after an export:

```python
{
    "artifact": "my_scan",
    "bundle_dir": ".../exports/my_scan_artifact",
    "remote_root": "/evidence",
    "remote_path": "/evidence/my_scan_artifact",  # absent when no_upload=True
    "encrypted": True,
    "uploaded": False,        # build data; the exit code is authoritative
    "link_requested": True,
    "link_expire": "7d",
    "link": "https://mega.nz/folder/...",   # only when link=True and it worked
    "link_created": True,
    "link_error": "...",      # only when the upload succeeded but the link did not
}
```

A link failure never turns a successful upload into a failed export; check
`link_error` if you asked for a link.

### Retrieve (download + verify)

`retrieve(...)` blocks. `start_retrieve(...)` takes the same keyword arguments.

```python
client.retrieve(
    "my_scan",
    mode="restore",         # "restore" = verify then safely extract (default)
                            # "recover" = download + verify the archive only
    remote_root=None,
    dest=None,              # restore target; default exports/<name>_recovered
    out_root=None,          # recover parent; default <repo>/exports
    timeout=None,
    force=False,            # recover: overwrite an existing local copy
    verify_only=False,      # restore: no network, verify a local bundle
    bundle=None,            # restore + verify_only: the <name>_artifact dir
)
```

`mode="restore"` verifies the archive digest **before** extraction and then
checks every extracted file against `manifest.json`. `mode="recover"` stops
after the digest check, which is the cheap way to prove remote bytes are intact.

`result.data`:

```python
# restore, network
{"artifact": "my_scan", "mode": "restore",
 "remote_path": "/evidence/my_scan_artifact",
 "dest": ".../exports/my_scan_recovered", "network": True}

# restore, verify_only
{"artifact": "my_scan", "mode": "restore",
 "bundle": ".../exports/my_scan_artifact", "dest": "...", "network": False}

# recover
{"artifact": "my_scan", "mode": "recover",
 "remote_path": "/evidence/my_scan_artifact",
 "out_root": ".../exports", "local_path": ".../exports/my_scan_artifact",
 "network": True}
```

## Jobs

Anything that talks to MEGA can take long enough that a request handler should
not wait. `start_export()` / `start_retrieve()` return a `Job`.

```python
job = client.start_export("my_scan", link=False)
job.data        # the same dict export() would report
job.pid
job.running()
job.poll()      # None while running, else the exit code
job.lines()     # captured stdout, newest last (ring buffer)
job.dropped()   # lines lost to the buffer
job.cancel()
result = job.wait(timeout=600)   # CommandResult; cancels + raises on timeout
```

`wait()` raises `MegaJobTimeout` if the deadline passes, after killing the
process. Stderr is folded into stdout, because the `mega/` scripts write all
narration to stdout.

`Job` has no link step. If you want a link, call `client.link(name,
create=True)` once `wait()` returns exit code 0.

## `CommandResult`

```python
result.command      # argv actually run
result.returncode   # the script's exit code
result.stdout       # captured narration
result.stderr       # usually empty (stderr is folded into stdout for jobs)
result.data         # the dict described above
result.ok           # returncode == 0
result.text         # stdout + stderr
result.require_ok() # raises MegaCommandError (with .result) on non-zero
result.to_dict()    # JSON-ready
```

Exit codes are the scripts' own contracts:

| `export` / `upload.py` | Meaning |
| --- | --- |
| `0` | bundle built, protected and uploaded |
| `1` | generic failure |
| `2` | bad arguments or unusable evidence |
| `3` | built, but MEGAcmd was unavailable — nothing uploaded |
| `4` | protection failed — nothing uploaded |

| `retrieve` / `recover.py` | Meaning |
| --- | --- |
| `0` | verified |
| `1` | generic failure |
| `2` | no session, or the destination already exists |
| `3` | MEGAcmd unavailable |
| `4` | checksum mismatch |
| `5` | artifact not found |

`restore.py` uses `1` for every failure, including an integrity mismatch, so
read `result.stdout` when you need to tell "wrong password" from "corrupt
archive".

## The remote contract

```
<remote_root>/
└── <name>_artifact/
    ├── <name>_evidence.tar.gz          archive of the evidence tree
    ├── <name>_evidence.tar.gz.sha256   "<digest>  <filename>"
    ├── <name>_evidence.zip             optional WinZip AES-256 wrapper
    └── manifest.json                   counts, sizes, digests, encrypted flag
```

The archive is deterministic: the same evidence tree produces the same digest,
which is what makes `dry_run=True` meaningful. `.env` and similar secrets are
excluded by `upload.py` and never reach the archive. Files are stored
sorted, and the manifest records `file_count` plus every relative path.

## Errors

All of them subclass `MegaSDKError`:

| Exception | Raised when |
| --- | --- |
| `MegaArgumentError` | bad artifact name, remote root, duration, mode, or missing bundle |
| `MegaNotAvailable` | MEGAcmd is not installed / not on `PATH` |
| `MegaNotLoggedIn` | no MEGAcmd session |
| `MegaRemoteError` | a MEGAcmd call failed |
| `MegaProtectionError` | password or zip handling failed |
| `MegaCommandError` | a script exited non-zero; `.result` holds the `CommandResult` |
| `MegaJobTimeout` | `Job.wait()` exceeded its deadline; `.lines` holds the tail |

`MegaArgumentError` also subclasses `ValueError`. Validate early: `bundle_path`
and `link` will reject `..`, separators, an empty name and the
`_artifact`-suffixed form.

## Environment

| Variable | Effect |
| --- | --- |
| `IA_REPO_ROOT` | repo containing `mega/` when `repo_root` is not passed |
| `MEGA_SECRETS_DIR` | where the sealed credential lives |
| `IA_BUNDLE_PASSWORD_FILE` | default bundle password file |
| `MEGA_AUTH_CODE` | login code for `mega/login.py` |
| `MEGA_FETCH_CMD` | overrides the remote fetch command |

## Inspect from the shell

```powershell
python stix-server/mega_client.py status
python stix-server/mega_client.py bundles --remote-root /evidence
python stix-server/mega_client.py links   --remote-root /evidence
```

## Tests

```powershell
# Local only: build, protect, decrypt, verify, Job, argument guards. No network.
python stix-server/smoke_test.py

# Also read the live listing and an existing link (read-only).
python stix-server/smoke_test.py --remote --remote-root /evidence

python stix-server/smoke_test.py --keep   # leave the temp bundle for inspection
```

## Things to know

* **The directory name has a hyphen.** `stix-server` cannot be imported as a
  package. Put it on `sys.path` (as above) or start your server from inside it.
* **`mega/` is not a package.** The loader registers modules in `sys.modules`
  *before* executing them, because `megacmd.py` defines a module-level
  `@dataclass` that fails to resolve on Python 3.13+. Do not "simplify" that
  ordering.
* **Paths are canonicalised.** On Windows, `tempfile.mkdtemp()` returns an 8.3
  short path (`C:\Users\THE4TH~1\...`), and `restore.py` compares that against
  the long paths `os.walk` reports. `MegaClient` calls `.resolve()` on every
  local path it forwards to avoid the mismatch.
* **`stix-server/` is currently invisible to git.** The repo's `.gitignore`
  ignores everything by default and whitelists files; add the directory (and
  deny `__pycache__`) if you want this SDK tracked.
