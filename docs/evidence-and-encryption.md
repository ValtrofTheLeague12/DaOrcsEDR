# Evidence bundles, protection and output

What gets written, where, and what happens to it before it leaves.

<!-- Source: README.md, split by topic. -->

### Evidence bundle and upload options

The analyzer always writes its normal report files to
`exports/<sample>_analysis/`. Optional packaging and MEGA upload are controlled
in `config/artifacts.yaml` (also copied beside the built executable), with the
transfer half (`upload_artifacts`, `remote_root`, `timeout_seconds`) now living
as MEGA_* settings in `config/analysis.yaml`, which wins wherever both files
define one:

```yaml
store_artifact: false
upload_artifacts: false   # set as MEGA_UPLOAD in analysis.yaml now
remote_root: /            # set as MEGA_REMOTE_ROOT in analysis.yaml now
encrypt_artifacts: false
timeout_seconds: 900      # set as MEGA_TIMEOUT in analysis.yaml now
```

Set `store_artifact: true` to create
`exports/<sample>_artifact/` with a deterministic tar.gz, SHA-256 sidecar,
file manifest, and README. Set `upload_artifacts: true` to also upload that
bundle through MEGAcmd; uploading automatically creates the local bundle first.
Cloud upload is opt-in and requires MEGAcmd to be installed and logged into the
intended account. `remote_root` is the destination parent, and the bundle is
placed in `<remote_root>/<sample>_artifact`. A configured packaging or upload
failure is reported and causes the analyzer to exit unsuccessfully; the run
manifest records the options, resulting bundle paths, and any error. Missing
configuration uses safe defaults (no packaging or upload).

### Bundle protection

`encrypt_artifacts: true` (or `MEGA_SEAL: true` in analysis.yaml) wraps the
archive in a **password-protected zip** before anything is uploaded, so the
copy that lands on a third-party account is not readable by the provider, a
leaked session, or anyone who finds a shared link.

```yaml
encrypt_artifacts: true
```

The password itself is NOT a config value anywhere. It lives in the operator
password file outside the repo:

```text
%APPDATA%\IAProject\bundle-keys\upload.password     (or IA_BUNDLE_PASSWORD_FILE)
```

The admin console's Analysis Configuration page manages that file: show its
state, set a password you choose, generate one (the value is returned exactly
once, and the page shows it with a copy button — never again), or clear it. The
minimum is 8 bytes; what is stored is exactly what you gave, with at most one
trailing newline tolerated and stripped on the way out, because editors always
add one and the password must round-trip byte-exact.

The scheme (implemented with the Python `pyzipper` library **in-process** — no
`gpg`, no `openssl`, no shell):

| part | construction |
|---|---|
| container | one ZIP member — the deterministic archive |
| encryption | WinZip AES-256 (`WZ_AES`), the ZIP standard's AES extension — not legacy ZipCrypto |
| per-entry | random salt (256-bit), password-verification value, HMAC over the entry, per 64 KiB block salted updates |

Every entry has an HMAC and a password-verification value stored in the AES
extra field, so a wrong password, an altered file or a truncated one fails
closed instead of producing garbage. A lost password means the bundle is
unrecoverable — there is deliberately no recovery path. Generating the password
and copying its only showing is how that risk is managed.

**Where the password beats the keypair it replaced:** no key generation, no
private half that every consumer of the bundle must fetch from this machine,
and no second key class ("admin") whose public file had to be sourced from the
lab. Whoever should open the remote bundle gets the password; everyone else,
including the MEGA account itself, gets ciphertext.

When protection is on:

- the plaintext archive stays on local disk; only the `.zip` is uploaded,
  staged into a temporary folder so a plain `put <folder>` cannot sweep the
  plaintext up alongside the ciphertext;
- if protection **fails, the upload is aborted** (exit 4) rather than falling
  back to plaintext — a missing password file cannot silently downgrade the
  bundle;
- the manifest and README record the algorithm, format and library, and the
  SHA-256 of the protected bytes (never the password, never the local password
  file's path — the manifest itself travels to remote storage);
- `run_summary.json` gains `artifact_bundle.encrypted`, and the Artifacts
  page's **Export** button reads **Export to MEGA** when protection is on and
  **Export unprotected** when it is not.

To open a protected bundle, on any machine that has the PASSWORD:

```powershell
python mega/protect.py status                            # whether a password is set (no echo)
python mega/protect.py unzip quick_test_evidence.zip --out-dir .   # needs the password
python mega/protect.py zip quick_test_evidence.tar.gz --out quick_custom.zip    # re-protect
```

The legacy `python mega/seal.py` keypair tooling still decrypts `.enc` bundles
made by older checkouts, but nothing produces them any more.

## Output layout

### Where generated files live

Nothing the project *generates* is written into the source tree. Everything
lands under one directory named after the application, so a reader who finds it
knows they have found all of it:

```text
%APPDATA%/IAProject/           (Windows; XDG_DATA_HOME or ~/.local/share elsewhere)
  logs/          run logs, crash reports + minidumps, debug dumps, resume
                 checkpoints, trace.txt, YARA rule caches
  cache/         provider and tool caches (capa, CTI knowledge, ...)
  panel-cache/   the admin panel's own cache
  bundle-keys/   the bundle password file and the legacy keypairs
  mega-secrets/  sealed MEGA credentials
```

`IA_APPDATA_DIR` relocates the whole tree. The three implementations of this
resolver — `include/core/app_paths.hpp`, `python/panel/config.py` and
`admin-terminal/core.py` — are deliberately the same rule, because the analyzer,
the panel and the terminal all read each other's output.

Two directories stay in the repository on purpose:

- `exports/` — analysis results, relative to the working directory. These are
  deliverables: what an operator browses, opens and hands to someone else.
- `data/` — the reference corpus (`known_pe_hashes.jsonl`), checked in.

### Analysis results

```text
exports/<stem>_analysis/
  fileinfo/       file metadata and magic/header information
  hash/           SHA-256 and fuzzy hashes
  extraction/     sections, strings, guards, packing, signatures, opcodes
  ioc/            extracted IPs, domains, URLs, e-mails, hashes, family hints
  iat/            PE import table data
  got/            ELF/Mach-O GOT/PLT data
  capa/           capa capabilities and technique mappings
  radare2/        functions, assembly JSON, call graph DOT, section CFG DOT
  malapi/         structured MalAPI hits
  cti/            provider findings, correlation, and CTI summary
  known_pe/       corpus-membership result for the sample's SHA-256
  stix/           STIX 2.1 bundle and ATT&CK Navigator layer
  dashboard/      final self-contained HTML report
```

Every run gets its own `<stem>_analysis/` directory under `exports/`, named after the sample's
stem, so two runs never read or overwrite each other's artifacts and re-running the same sample
replaces only its own results. The shared caches (`cache/`, `cti-cache/`, `data/`) stay outside
the per-run directory.

JSON artifacts are composable. The dashboard generator reads these files and embeds a normalized payload into one HTML document, so the report can be opened locally without a web server or network fetch.

