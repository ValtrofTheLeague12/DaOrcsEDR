# Utils

<!-- Source: README.md, split by topic. -->

#### Utils

Four things that can only be maintained by knowing the repo layout. Each is a
card with its own action, because they are not variants of one operation — one
rewrites two JSON files, one runs `git pull`, one compiles three thousand rules,
one downloads 794 MB. `GET /api/utils` reports all four; `POST /api/utils` with
`{"ids": [...]}` runs the chosen ones as a job.

| card | state it reports | action |
| --- | --- | --- |
| **SBOM** | component counts, age, and whether it predates the last commit | rewrite `sbom.json` + `sbom_summary.json` |
| **MalAPI rules** | `malt/` branch, commit, ahead/behind, dirty count | `git pull --ff-only` |
| **YARA rules** | collections, counts, `yara` version | compile every rule file |
| **yarGen-Go** | `dbs/`, `config.yaml`, `yargen.exe`, Go toolchain | run `update_and_check.ps1` |

"Update MalAPI" means updating the **rule source**: MalAPI itself is not
vendored, and the analyzer talks to a generated local API
(`python/api/server.py`, 544 routes) built from `malt/`. The pull is
`--ff-only` with `GIT_TERMINAL_PROMPT=0`, and it refuses outright if `malt/`
has local changes — a browser button cannot be allowed to create a merge
commit, block on a credential prompt with no terminal to answer it, or discard
uncommitted work.

`yara-rules/` deliberately offers **no** update. It is five unpacked
collections with no recorded upstream, so the card says that rather than
omitting a button the admin expects to find.

**The rule compile check is per-file, and that is a real limitation.** Neither
`yarac` nor `yara` in 4.5.8 accepts a directory, and concatenating a collection
into one file collides on duplicate rule identifiers, so it is one process per
file — from that file's own directory, or the 132 `Malekith_Rules` files with
relative includes all report a false "can't open include file". Results are
therefore split into four buckets rather than pass/fail, because a single
verdict would be a lie:

| bucket | meaning | verdict |
| --- | --- | --- |
| compiled | valid on its own | ok |
| `unknown module` | wants a YARA module this build lacks (`androguard`, `cuckoo`) — the rules are fine | informational |
| `undefined identifier` | references a sibling rule file; the pack is interdependent and the analyzer resolves these through its own include callback at scan time | informational |
| anything else | a real syntax or include error | **fails** |

That last bucket is the point of the card. As shipped it finds **7 dangling
`include` directives** in `Malekith_Rules` — `index.yar`, `index_w_mobile.yar`,
`rules/index.yar`, `rules/index_w_mobile.yar`, `rules/malware_index.yar`,
`rules/webshells_index.yar` and `webshells_index.yar` all reference
`./webshells/WShell_THOR_Webshells.yar` or `./malware/MALW_AZORULT.yar`, and
neither target exists anywhere in the pack. The analyzer tolerates this — its
scanner logs to `logs/yara_errors.log` and returns `CALLBACK_CONTINUE` — which
means those rules **silently never load during a scan**.

