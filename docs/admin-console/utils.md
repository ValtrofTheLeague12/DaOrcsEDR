# Utils

<!-- Source: README.md, split by topic. -->

#### Utils

Five maintenance surfaces, grouped into four tabs - Detection content,
Software inventory, Generator resources and the run log. Four of them report
through `GET /api/utils` and run through `POST /api/utils` with
`{"ids": [...]}`; generator resources is not a utility job and has its own
endpoints (below). Each is a card with its own action, because they are not
variants of one operation — one rewrites two JSON files, one mirrors a website
and regenerates a server, one compiles three thousand rules, one downloads
794 MB, one fetches value lists over http(s).

| card | state it reports | action |
| --- | --- | --- |
| **SBOM** | component counts, age, and whether it predates the last commit | rewrite `sbom.json` + `sbom_summary.json` |
| **MalAPI classification** | mirror age, definition count, whether the generated API is older than its mirror, httrack presence, stale lock | re-mirror `malapi.io` and regenerate, then boot the result |
| **YARA rules** | collections, counts, `yara` version | compile every rule file |
| **yarGen-Go** | `dbs/`, `config.yaml`, `yargen.exe`, Go toolchain | run `update_and_check.ps1` |
| **Generator resources** | per source: value count, last good fetch, last failed fetch | add a URL, refresh it, disable or remove it |

## Generator resources

The Build page's sample factory samples bait values from four pools: malicious
IPs, domains, URLs and file hashes. This tab is where those pools are
maintained; the factory shows their sizes and disables **Resource IOCs** while
either of the two it requires (IPs and domains) is empty. How each sampled value is stored in the generated source - plain,
ROT13, XOR, Base64 or a per-value `mixed` - is the factory's **IOC encoding**
option, not another pool.
The point of `mixed` is that one generated sample carries several shapes drawn
from the same lists, so the deobfuscation passes have something to peel back.

The repository ships with two definitions already configured:
`malicious-ips` (`romainmarcoux/malicious-ip`, 40,000 addresses) and
`malicious-domains` (`romainmarcoux/malicious-domains`, 130,814 hostnames from
`full-domains-aa.txt` after the last refresh). They are ordinary resources:
refresh, disable or remove them like any other. The dumps are not tracked, so a
fresh clone starts with both pools empty and one **Refresh** each fills them.

**These are bait literals, not detection knowledge.** Nothing here is loaded as
a rule, nothing is trusted, and nothing is dialled: the factory copies one
sampled value into the generated C/C++ source, encoded as selected. The page says
that in as many words because a list titled "malicious IPs" invites the opposite
assumption.

| pool | line format | what the factory does with it |
| --- | --- | --- |
| Malicious IPs | one IPv4/IPv6 address first on each line; a comma, space or semicolon and anything after it is ignored. Blocking addresses (`0.0.0.0`), loopback, link-local and multicast are skipped: they are not IOCs | **Resource IOCs** plants one address and one domain, each stored in the selected encoding |
| Domains | one hostname per line, or a hosts-file line (`0.0.0.0 evil.example`), which is read as its hostname; lowercased, a leading `*.` and a trailing dot are dropped | the other half of **Resource IOCs** |
| URLs | one whole `http://` or `https://` URL per line, no spaces; the path and query are kept verbatim | one URL is planted too, and the analyzer's IOC extractor reports it as a URL |
| File hashes | one hex digest per line: 40 characters (SHA-1), 64 (SHA-256) or 128 (SHA-512). A `sha1:`/`sha256:`/`sha512:` prefix and uppercase are accepted and normalised to lowercase. The digest may sit in any column (`<digest>,first seen`, `SHA256,<digest>`) | one digest is planted, the shape a file-hash feed publishes |

Each pool is sampled independently, so a filled pool adds one more literal to
every generated sample that has **Resource IOCs** enabled. The two the checkbox
requires are still IPs and domains; URLs and file hashes are optional extras.

*Where entries come from.* Any `http(s)` URL on any host: GitHub (including a
`github.com` file page, which is rewritten to its raw URL - the page shows the
normalised URL it actually fetches), a gist, a CDN, a paste service or your own
server. URLs carrying credentials are refused, since they would be written to
the definitions file in clear text, and a redirect must still land on `http(s)`.
Each fetch is capped at 16 MiB and 200,000 values per source (community IOC
dumps are routinely tens of thousands of lines); up to 32 sources are allowed in
total.

*Parsing is auditable.* Lines that do not fit the kind are counted and reported
("3 line(s) skipped"), duplicates are dropped and counted, and a file that
yields no usable values is refused rather than cached as an empty pool. The
first three values are previewed on the card.

*Failure never empties a pool.* A failed refresh keeps the last good values and
records the error beside them, so the card can say both "fetched two days ago"
and "the refresh an hour ago answered HTTP 404" - the operator decides whether
that bait is still current. If the URL or kind is edited, both the dump and the
parsed values are dropped instead: yesterday's list must not answer for a new
address under a new label.

*Storage.* Definitions live in `config/sample_resources.json` and are
panel-owned. Each fetch writes the bytes the server served to
`ressources/<id>.txt` (the card shows that path) and the validated values plus
fetch bookkeeping to `ressources/<id>.json`. Neither file is in git: they are
large, regenerable, and stale the moment upstream moves. A definitions file
that cannot be parsed is reported and never overwritten - fix or remove it
before adding anything.

Endpoints: `GET`/`POST /api/utils/resources`,
`PUT`/`DELETE /api/utils/resources/<id>`, and
`POST /api/utils/resources/<id>/refresh`. Every mutation returns the fresh
snapshot. A refresh that fails still answers `200` with `ok: false` and the
snapshot, because the page needs the error AND the last good values in one
render.

## The MalAPI card

**`malt/` is not the rule source, and updating the rules does not touch it.**
They are different things with confusingly similar names:

| | what it is | who updates it |
| --- | --- | --- |
| `malt/` | `github.com/memtt/malt` — the MalAPI **tool**, a C++ memory-forensics project (CMakeLists, `src/`, `extern-deps/`) | nobody from this console |
| `python/malapi/` | a **mirror of malapi.io**, scraped with `httrack` | the card |
| `python/api/server.py` | the **generated** Flask API the analyzer queries — 544 routes over 369 MalAPI and 175 LOTS definitions | regenerated from the mirror |

The card reports `malt/`'s commit and remote under the name `malt_tool`, with
`used_by_analyzer: false` and a note saying so, because an operator who knows
the directory exists deserves to be told what it is rather than left to assume
it feeds the analyzer. It never had: nothing the analyzer runs links `malt/`.

**"Update" means re-mirroring, not pulling.** malapi.io publishes no version to
pull against, so "up to date" is not a state this card can report — the only way
to know is to re-mirror and regenerate. The action is one script,
`python/malapi_pipeline.py --with-scrape`, which runs three stages:

```
python/malapi/malapi.io/     scraped site      (httrack, under WSL)
        │  _extract_files.py + _map_to_yaml.py
        ▼
python/yaml/malapi/          369 .yaml definitions
        │  _create_api.py  +  python/templates/abuse.py.j2
        ▼
python/api/server.py         Flask app, 544 routes   ← what the analyzer queries
```

It then **boots the server it just generated, queries it, and shuts it down**
again, on port 60111 rather than the analyzer's 60000 so it cannot collide with
a run in progress. That is the point of the stage: a regenerated server that
does not answer would otherwise be reported as a successful update, and
`python/api/server.py` is only useful if it actually answers. Every stage runs
with the working directory set to `python/`, because the generators resolve
their inputs relative to the current directory rather than their own location.

The card declares the same four effects it performs, so the cost is legible
before the button is pressed: it reaches the network, rewrites `python/malapi/`,
rewrites `python/yaml/malapi/`, rewrites `python/api/server.py`, and removes a
stale httrack lock.

**Refusal is a real state, and which lock is which matters.** A leftover
`hts-in_progress.lock` makes `httrack` refuse to start at all, so the card
reports `blocked` with the reason rather than starting a run that will fail
partway through. But the two ages are opposite:

| lock age | verdict | why |
| --- | --- | --- |
| under a day | **blocked** | it may be a live mirror; the run refuses to touch it |
| over a day | **warned, still runnable** | the scrape stage clears it itself before mirroring and says so |

`blocked` is about the *action*, not about the rules: the mirror, the
definitions and the generated server are all still there and still serving. A
missing mirror is the strongest reason to press the button, not a reason it is
disabled — the scrape stage builds it from nothing, which is what it is for.

This card used to run `git pull --ff-only` on `malt/`. That was the wrong
repository, and it was retired — but the prose describing it outlived the code,
which is why this section exists.

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

## The output pane

The run's output is colourised, and the rule for how is worth stating because it
is the same rule the YARA buckets above follow: **colour means "look here", the
left rail means "stop scrolling"**.

The four utilities do not log — they emit about a dozen shapes of their own and
then whatever `git`, `generate_sbom.py` or `yarac` printed. The page's own shapes
are matched first, and everything unmatched is handed to the shared log
colouriser, which already knows timestamps, level words and ANSI. So a child
process that speaks its own dialect still gets coloured.

| line | colour | rail |
| --- | --- | --- |
| `FAIL <path>: <error>` | red | yes |
| `N file(s) genuinely failed to compile:` | red | yes |
| `--- <utility>: FAIL` / `PASS` | red / green | yes |
| `--- <utility>: SKIPPED (<reason>)` | amber | yes |
| `=== N passed, M failed` | red when `M > 0`, green when `0` | yes |
| `skipped unknown utility id(s)` | amber | yes |
| a traceback, a timeout, `OSError:`-shaped failure | red | yes |
| `N file(s) reference identifiers…` / `need a YARA module…` | dimmed | no |
| `=== <utility>` and the `$ <command>` under it | accent | no |
| `... N file(s) checked…` (every 15s) | dimmed | no |

Two of those rows are the ones that would be wrong to colour loudly. The two
informational buckets are **not** defects — they are the counts above, and the
backend already explains each in the sentence beneath it — so they are dimmed
and get no rail. A progress line is not news, and colouring it would colour all
three thousand of them. Painting an informational bucket as loudly as a genuine
failure is how a log viewer teaches people to stop reading it.

The header carries the count of red/amber lines and the job's exit code, so the
answer to "did anything break" is above the log instead of inside it.

