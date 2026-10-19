# Getting started

One binary, one path, one staged pipeline.

<!-- Source: README.md, split by topic. -->

## What the project does

`static_analyzer.exe` takes one binary path as its input and runs a staged static-analysis pipeline. It reports information to the terminal and writes normalized JSON, assembly, graph, CTI, and HTML artifacts under `exports/<stem>_analysis/` — one directory per run, so samples never share paths. The pipeline has 25 numbered stages, of which a given run executes 20 or 23 depending on the detected format — see [How a run works](getting-started.md#how-a-run-works).

The pipeline is designed around five ideas:

1. **Understand the file** — format, headers, sections, entropy, imports, symbols, strings, guards, and packing indicators.
2. **Extract intelligence** — URLs, domains, IPs, e-mail addresses, hashes, family hints, CVE/ATT&CK-related data, and provider findings.
3. **Understand behavior statically** — capa capabilities, radare2 functions, instruction data, call graphs, section CFGs, and IAT/GOT call sites.
4. **Export evidence** — machine-readable JSON and DOT artifacts suitable for automation.
5. **Present the result** — a self-contained offline HTML dashboard with maps, graphs, assembly, hexdump, CTI summaries, and detail panels.

## How a run works

### Invocation and startup

```text
static_analyzer.exe <input-file>
```

With no argument the analyzer falls back to `a.exe` in the current directory. Results are written relative to the working directory, so run from the repository root unless a different layout is intentional.

### Python API server

The root `server.py` provides a local REST API. Start it from the repository root
with:

```powershell
python\.venv\Scripts\python.exe server.py
```

Set `SA_API_HOST` and `SA_API_PORT` in `.env` to configure its bind address and
port (defaults: `127.0.0.1:60020`); command-line `--host` and `--port` override
those settings. The JSON service index is available at the configured address.
Submit samples with `POST /analyze` as a multipart `file` upload or raw request
body; use `--analyzer` to select a different analyzer executable.
During graceful shutdown, GET endpoints remain available for status and task
inspection, while new POST submissions receive `503`.
Run `python\.venv\Scripts\python.exe tests\test_server_queue.py` to test queuing
the included executable fixture and graceful draining without launching the analyzer.

## Running the analyzer

The command-line interface is positional:

```text
static_analyzer.exe <input-file>
```

Example:

```powershell
.\build-ucrt\static_analyzer.exe .\a.exe
```

With no path, the program defaults to `a.exe` in the current working directory. The analyzer writes results relative to the current working directory, so run it from the repository root unless a different output layout is intentional.

