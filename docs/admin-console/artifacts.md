# Artifacts

<!-- Source: README.md, split by topic. -->

#### Artifacts

`GET /api/artifacts` reads both ends of the `mega/` evidence pipeline, split into
a **Local artifacts** tab and a **Remote** tab.

Local walks `exports/` for `<artifact>_artifact/` bundles and reports the sealed
`<artifact>_evidence.tar.gz`, the file count from `manifest.json`, and the
SHA-256 that the manifest and the `.sha256` sidecar each recorded
independently. The archive is re-hashed where a byte budget allows, so a bundle
that is present but truncated reports *digest mismatch* rather than looking
fine; anything over budget reports *not hashed*, because "unverified" and
"verified" must never look alike.

Remote lists the same bundles off MEGA through `mega/list.py` — loaded by path,
so its own `ls()` parser is used and its handling of MEGAcmd's two date shapes
is inherited rather than reimplemented. It is a third-party call, so a missing
MEGAcmd, an absent session and a timeout all degrade to `available: false` with
a reason, under a 25-second wall-clock budget so a slow MEGA cannot hold the
request open. A truncated listing says so instead of looking complete.

**The upload timeline is cached, so the charts are continuous.** Every
successful remote read is folded into
`%APPDATA%\IAProject\panel-cache\artifacts-history.json` (override with
`IA_PANEL_CACHE_DIR`, same convention as `mega/credential.py`'s `secrets_dir()`,
and deliberately outside the repo tree), and the transfer series is computed
from *that* rather than from whatever MEGA is holding right now. Three
consequences, each of which is the point:

- **It survives a panel restart.** The in-memory cache dies with the process;
  the timeline does not.
- **Deleting a case from MEGA does not erase its point.** The upload still
  happened, so the bundle stays on the timeline marked *no longer on MEGA* and
  keeps contributing the interval it formed. Dropping it would make the rate
  jump as though the case had never existed.
- **A logged-out client cannot wipe the record.** History is only written on a
  successful read, so a failed probe leaves the last good data in place and the
  panel says "last successful read 4 minutes ago" instead of showing an empty
  account.

Re-polling every 30 seconds does not invent new points: entries are keyed by
name and keep MEGA's *upload* timestamp rather than the time we looked, so the
same bundle observed a hundred times is still one point. The file is written
atomically (temp + rename, so a crash mid-write cannot leave a half-file that
the next read discards), is rebuilt rather than trusted if it is corrupt or
wrong-shaped, and is capped at 500 bundles, keeping the newest.

**Refresh rates, and why they are slow.** Nothing on this page changes on a
timer: a bundle is sealed when an analysis run finishes, and MEGA changes when
someone presses upload. Both are human actions, so the panel polls every 120 s
and the server caches the MEGA listing for 5 minutes — 12 MEGAcmd spawns an
hour instead of 60, for a detection latency no one can perceive. `?refresh=1`
bypasses both caches, which is what the Rescan button uses so that "I just
uploaded, show me" does not mean "wait five minutes".

The relative "x ago" labels deliberately do **not** ride that interval. They
tick on their own 60-second clock (`admin-web/src/lib/tick.ts`) and cost no
request, so a clock tick can never trigger a MEGAcmd renewal as a side effect.
The two questions — how often the data refreshes, and how often a label
describing a fixed timestamp changes — are answered separately.

One thing to know about `usePoll`: it holds the fetcher in a ref rather than
listing it as an effect dependency. Listing it was a live bug — a caller
passing an inline arrow (which this page needs, for `?refresh=1`) produced a new
function identity every render, so the effect re-ran, set state, re-rendered,
and looped. The result was not "poll every 120 s" but polling as fast as the
endpoint would answer, which looks exactly like values updating too fast.

**The upload-rate charts are estimates, and the panel says so on the card.**
Nothing in this project records when an upload *starts* — MEGAcmd records only
when it finished — so a true per-upload duration is not knowable from the data
that exists. What the charts show is the later bundle's bytes divided by the
wall-clock gap between the two MEGA timestamps. That gap also contains however
long the operator waited before pressing upload, which makes the figure an
upper bound on line rate and never a measurement of it. Gaps under one second
render as no value rather than as an infinite speed, because MEGAcmd's date is
minute- or day-granular and a near-zero gap divided by real bytes is a
granularity artefact. One bundle has no interval and therefore no rate; the
chart says so instead of drawing a zero.

The page reports; it does not push. Uploading is available as an explicit
**Export to MEGA** action per bundle on the Remote tab, and it is gated on
`upload_artifacts` in `config/artifacts.yaml` — the same switch that decides
whether an analyzer run uploads anything. That option is the operator saying
"this lab does not send evidence off the host", so a button in a browser has to
obey it exactly as the binary does; with it off the button is disabled and the
page says where to turn it back on. Recover is never gated: pulling evidence
down does not send it anywhere.

Export runs `mega/upload.py` as a job rather than reimplementing it, because
that script owns the determinism guarantees (sorted members, normalised mtimes,
the checksum taken over the finished file) and a second uploader would quietly
be a different thing producing different bytes under the same name. Sealing a
large bundle and pushing it over a consumer link takes minutes, so it returns a
job handle and the page polls for the log — the same job modal a `docker compose
build` uses, which is why that modal is a component rather than a copy. A
successful export invalidates the five-minute MEGA listing cache; otherwise the
button would work and the page would insist nothing had arrived.

