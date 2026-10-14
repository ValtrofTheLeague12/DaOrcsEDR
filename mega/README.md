# mega - evidence storage and backup

Seals one analysis run into `<artifact>_artifact/`, then hands it to MEGA.

```
exports/quick_test_analysis/        evidence source (the analyzer's output)
        |
        |  upload.py
        v
exports/quick_test_artifact/
        quick_test_evidence.tar.gz          tar + gzip (zlib)
        quick_test_evidence.tar.gz.sha256   <digest>  <filename>
        manifest.json                       per-file inventory + digest
        README.txt                          what, when, where-from, digest
        |
        |  MEGAcmd (put -c, via megacmd.py) -> /quick_test_artifact/
        v
```

## credential.py - AES-256-GCM sealing

```bash
# seal: generates a 256-bit key, writes it to mega/credential.key,
# encrypts into mega/credentials.enc
python mega/credential.py seal --from cred.json
python mega/credential.py check          # validate without printing
python mega/credential.py open           # print the plaintext JSON
```

`cred.json` is `{"email": "...", "password": "...", "app_key": "..."}`.
`email` and `password` are required; `app_key`, `root_node` and `api_url` are
optional and anything else is rejected rather than silently ignored.

File layout, so a damaged or truncated seal is detectable rather than
cryptographically confusing:

```
offset size  field
0      8      magic "MEGACRED"
8      1      format version
9      1      key mode: 1 = keyfile, 2 = scrypt
10     1      reserved, must be 0
11     1      scrypt log2(N)
12     16     scrypt salt (zeroed in keyfile mode)
28     12     GCM nonce
40     ..     ciphertext || 16-byte tag
```

The header is passed to AES-GCM as additional authenticated data, so the mode
and version bytes cannot be edited either. Verified against 11 cases: wrong
key, wrong passphrase, flipped ciphertext bit, flipped header byte, truncated
file, bad magic, short key file, and a keyfile seal offered to the passphrase
path - all rejected; roundtrips clean; two seals of identical plaintext differ
because the nonce is fresh each time.

### Where the key is

**`%APPDATA%\IAProject\mega-secrets\`** - `credentials.enc` and `credential.key`,
kept deliberately **outside the repo tree**.

```
%APPDATA%\IAProject\mega-secrets\
    credentials.enc      AES-256-GCM ciphertext
    credential.key       32 raw bytes, THE secret
```

Co-location with the code was the one weakness in this scheme, so the pair is
not in the working directory at all: `git add -A`, a repo backup, or an archive
of the tree cannot reach it. Override the location with `MEGA_SECRETS_DIR`; the
single definition is `credential.secrets_dir()`, which `login.py` and
`upload.py` both read rather than each guessing a path.

Both files are locked down on creation: `os.open(..., 0o600)` *before* the
bytes are written, then on Windows `icacls /inheritance:r /grant:r <user>:F`,
which removes inherited ACEs so no group or Everyone entry survives. A move to
the secrets directory re-applies this rather than assuming a same-volume rename
preserved it. Confirmed after the move:

```
credential.key    DESKTOP-2SIC57C\The4thReich:(F)
credentials.enc   DESKTOP-2SIC57C\The4thReich:(F)
```

**Be clear-eyed about what this buys you.** The key still sits on the same disk
as the ciphertext, so anyone who can read the secrets directory reads both, and
the ciphertext never had to travel. What changed is that the secret is no
longer inside the tree that gets copied, committed and archived all day. It is
not a second factor - for that, use scrypt mode below and delete the key file
entirely.

If you ever find a pair back in `mega/`, migrate it with:

```bash
python mega/credential.py relocate
```

It moves both files, re-hardens the ACLs, and decrypts at the destination to
confirm the pair still opens before reporting success.

If you can type a passphrase when you need it, use scrypt mode instead and
delete the key file entirely:

```python
# in credential.py: seal(payload, enc, passphrase=...) / open_sealed(enc, passphrase=...)
```

scrypt N=2^15, r=8, p=1 into the same AES-256 key. There is no key file to
leak. The trade-off is real: lose the passphrase and the credential is gone
permanently, with no recovery path.

## login.py

Opens the sealed credential - AES-256-GCM by default, GPG if that is the only
seal present, so an older `credentials.gpg` still works. The plaintext is only
ever in memory and on stdout; it is never written anywhere.

```bash
python mega/login.py --emit check          # validate only, prints nothing secret
python mega/login.py --emit json           # {"email": ..., "password": ...}
python mega/login.py --emit env            # EMAIL=... / PASSWORD=...
python mega/login.py --emit check --mega   # also make sure MEGAcmd has a session
```

`--mega` is what `upload.py`, `list.py` and `recover.py` need underneath. It
checks `whoami` **first**, and MEGAcmd persists its session, so on a machine
that is already signed in the password is never read at all. Only an account
with no session triggers a login, and MEGAcmd accepts a password solely as a
command-line argument - visible to anything that can read the process list - so
that step needs an explicit `--allow-password`. MFA codes come from
`MEGA_AUTH_CODE`, not argv.

## MEGAcmd on Windows vs Linux

`megacmd.py` is the only place that knows this. There is no `megacmd.exe`.

| | POSIX | Windows |
|---|---|---|
| CLI binary | `megacmd` | `MEGAclient.exe` |
| per-command shim | - | `mega-<cmd>.bat` |
| default location | `/usr/bin` | `%LOCALAPPDATA%\MEGAcmd` |

`MEGAcmdShell.exe` is an interactive terminal and is explicitly excluded: it
takes no argv command, no stdin command, and never exits, so anything that
picks it up hangs forever. `megacmd.py` also finds the install through
`MEGAcmd_HOME`, PATH, and `%LOCALAPPDATA%`, and gives every call a timeout.

## upload.py

```bash
python mega/upload.py --artifact quick_test --dry-run
python mega/upload.py --artifact quick_test
python mega/upload.py --artifact quick_test --no-upload      # bundle only
python mega/upload.py --artifact quick_test --remote-root /Cases/2026-10
python mega/upload.py --artifact quick_test --expect-account a@b.com
```

| flag | |
|---|---|
| `--artifact` | name; the bundle is `<artifact>_artifact` |
| `--source` | evidence dir (default `exports/<artifact>_analysis`) |
| `--out-root` | where the bundle goes (default `exports/`) |
| `--remote-root` | MEGA folder to upload into |
| `--no-upload` | build and verify, skip MEGA |
| `--dry-run` | also rebuild and prove the checksum reproduces |
| `--timeout` | seconds allowed for the upload |
| `--expect-account` | refuse to upload under the wrong MEGA account |

Exit codes: `0` ok, `1` failed, `2` bad arguments or missing evidence, `3`
bundled fine but MEGAcmd was unavailable, `4` not used by upload.

`--expect-account` defaults to the email inside the sealed credential, so the
wrong-account guard is on by default rather than something you have to remember
to pass. A run that ends in `4`... does not exist for upload; a recovered
bundle whose digest does not match returns `4` from `recover.py`.

### Three MEGAcmd behaviours upload.py works around

All three were measured against a live account, not read off the docs. They
are recorded in `megacmd.py` too, so they do not have to be rediscovered.

1. **`put -c` flattens.** If the destination does not exist and `-c` is
   allowed to create it, MEGAcmd writes the source folder's *contents* flat
   into the destination (`Upload finished: /<dest>`) with no wrapper folder. If
   the destination already exists, `put` nests normally. The only difference
   between "correct" and "silently wrong" is whether `mkdir` ran first - so
   upload.py always runs `mkdir -p` and then `put`. **The checksum cannot catch
   this**: the bytes are identical either way, they are just the wrong shape on
   the far end. Hence the post-upload re-listing.
2. **`put` nests**, so the destination is the *parent* of the artifact folder.
3. **`mkdir` is silent on success**, so its exit status alone does not prove
   the folder exists - hence the re-listing rather than trusting the code.

## list.py

```bash
python mega/list.py                                  # bundles at the MEGA root
python mega/list.py --remote-root /Cases/2026-10
python mega/list.py --details                        # plus the files inside each
python mega/list.py --json
python mega/list.py --all                            # every folder, not just bundles
```

Exit codes: `0` ok, `1` MEGAcmd failed, `2` no usable session, `3` no MEGAcmd.

## recover.py

```bash
python mega/recover.py --artifact quick_test
python mega/recover.py --artifact quick_test --remote-root /Cases/2026-10
python mega/recover.py --artifact quick_test --out-root recovered
python mega/recover.py --artifact quick_test --force
```

`get` exiting 0 only means MEGA finished moving bytes, so recovery re-hashes
the archive and compares it against the `.sha256` that travelled with it, and
cross-checks `manifest.json`. A mismatch means the recovered copy is not what
was uploaded and should not be trusted.

Exit codes: `0` verified, `1` MEGAcmd failed or no archive arrived, `2` no
session or a copy already exists, `3` no MEGAcmd, `4` **checksum mismatch**,
`5` nothing at that remote path.

Two more `get` behaviours, both found by testing:

- **The destination directory must already exist.** MEGAcmd will not create it;
  it fails with exit 55 and `is not a valid Download Folder`.
- **`-m` must not be passed.** With `-m` the bundle's contents merge flat into
  the destination and the wrapper folder never appears, so the verification
  would look for the archive in the wrong place.
- MEGAcmd also will not overwrite a destination folder whose contents differ; it
  writes a sibling suffixed ` (1)`. recover.py verifies whichever copy was
  written most recently rather than blindly trusting the expected path.

## Two properties worth keeping

**The checksum is over the uploaded bytes.** The tar is written and closed,
*then* hashed, *then* uploaded - so the SHA-256 in the README and in
`manifest.json` is provably the hash of what MEGA received, not of a stream
that was still being generated.

**The archive is deterministic.** Members are sorted and `uid`/`gid`/`uname`/
`gname`/`mtime` are normalised to fixed values, so rebuilding from the same
evidence yields a byte-identical tar and the same digest. `--dry-run` asserts
this. If it ever fails, that is a real finding, not tool drift.

This is why the gzip layer is driven directly rather than through `tarfile`'s
`w:gz` shorthand: that writes the current wall-clock time into the gzip header,
which changes the digest on every single run and makes the checksum worthless.

## What is never archived

`.gpg`, `.key`, `.pem`, `.env`, `cookies.txt`, `credentials.json`, and the
whole `mega/` tree. Verified by test, not by inspection.

## Current state

- The bundling, checksumming and verification work end to end. Verified against
  a real run: 26 files, 3,335,704 bytes -> 541,106 bytes, identical digest on
  rebuild.
- **Upload, list and recover are exercised against a live MEGA account.**
  Upload lands at `<remote-root>/<artifact>_artifact`, list reads it back,
  recover downloads it and re-derives the digest, and a deliberately corrupted
  archive is rejected with exit 4. The wrong-account guard refuses to upload.
- **The GPG roundtrip is still not exercised.** `gpg` is not installed on this
  machine. The decryption, validation and error paths are tested; the
  `gpg --decrypt` invocation itself is not.