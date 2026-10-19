# Evidence bundles, encryption and output

What gets written, where, and what happens to it before it leaves.

<!-- Source: README.md, split by topic. -->

### Evidence bundle and upload options

The analyzer always writes its normal report files to
`exports/<sample>_analysis/`. Optional packaging and MEGA upload are controlled
separately in `config/artifacts.yaml` (also copied beside the built executable):

```yaml
store_artifact: false
upload_artifacts: false
remote_root: /
encrypt_artifacts: false
encryption_recipient: user
admin_public_key: ""
timeout_seconds: 900
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

### Bundle encryption

`encrypt_artifacts: true` seals the archive to a public key **before** anything
is uploaded, so the copy that lands on a third-party account is not readable by
the provider, a leaked session, or anyone who finds a shared link.

```yaml
encrypt_artifacts: true
encryption_recipient: user     # or: admin
admin_public_key: ""           # only for recipient: admin
```

The scheme is a standard hybrid envelope, implemented with the Python
[`cryptography`](https://cryptography.io) library **in-process** — no `gpg`, no
`openssl`, no shelling out for the cryptography:

| part | construction |
|---|---|
| content | AES-256-GCM over the archive, in 1 MiB chunks |
| content key | 32 random bytes, fresh per bundle |
| key wrap | AES-256-GCM over the content key |
| wrapping key | HKDF-SHA256 over an X25519 ECDH |

Each chunk gets its own nonce (base nonce XOR chunk index, so a
(key, nonce) pair can never repeat) and binds the header plus its own index and
length as associated data, so chunks cannot be swapped, dropped or replayed. The
header is bound into every operation, so the recipient, algorithm and chunk size
cannot be edited either. A wrong key, an altered file, a truncated file or a
re-ordered one all fail loudly instead of producing garbage.

**Two recipients**, chosen per export:

- **`user`** — a keypair generated on this machine. `python mega/seal.py keygen user`
  writes it to `%APPDATA%\IAProject\bundle-keys\` (override with
  `IA_BUNDLE_KEYS_DIR`), outside the repo tree, with the file ACL stripped to
  your account on Windows. A lost private key means the bundle is unrecoverable —
  there is deliberately no recovery path.
- **`admin`** — the lab's public key, so evidence is sealed to whoever owns it.
  Only the **public** half is needed to encrypt, so the admin private key never
  has to exist on the machine producing evidence. Give it as base64 or PEM at
  `admin_public_key`, at `%APPDATA%\IAProject\bundle-keys\admin.pub`, or via
  `IA_BUNDLE_ADMIN_PUBKEY`.

When sealing is on:

- the plaintext archive stays on local disk; only the sealed file is uploaded,
  staged into a temporary folder so a plain `put <folder>` cannot sweep the
  plaintext up alongside the ciphertext;
- if sealing **fails, the upload is aborted** (exit 4) rather than falling back
  to plaintext — a broken key cannot silently downgrade the bundle;
- the manifest and README record the algorithm, the recipient and its key id,
  and the SHA-256 of the sealed bytes, so a copy of the bundle says what it is
  and who can open it;
- `run_summary.json` gains `artifact_bundle.encrypted`, and the Artifacts page's
  **Export** button reads **Export to MEGA** when sealing is on and **Export
  unencrypted** when it is not.

To open a bundle:

```powershell
python mega/seal.py inspect quick_test_evidence.tar.gz.enc   # header, no key needed
python mega/seal.py decrypt  quick_test_evidence.tar.gz.enc   # needs the private key
python mega/seal.py whoami                                   # this machine's key id
```

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
  bundle-keys/   evidence-bundle encryption keys
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

