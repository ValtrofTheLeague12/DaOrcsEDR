# Pipelines and analysis phases

What the stages are, which formats they apply to, and how to compose them.

<!-- Source: README.md, split by topic. -->

### Format detection and the phase plan

The file type is determined first, from libmagic plus LIEF, and reduced to one of **PE**, **ELF**, **Mach-O**, or unknown. That detection drives the plan, because several stages only mean something for one format:

- PE and ELF/Mach-O each have a dedicated section table, so the generic LIEF section view would be a duplicate and is dropped for them.
- Four stages are PE-only: the import table, the MalAPI lookup over its imports, the export address table, and the YARA rule scan.
- GOT/PLT is ELF/Mach-O only.

The arithmetic starts from 25 stages and subtracts what the format makes inapplicable, giving **23 for a PE**, **20 for an ELF or Mach-O**, and **20 for anything else**. The result becomes the progress total and the denominator in every `[phase n/total]` header. A stage the format excludes prints no header and advances nothing, so the numbering never runs past a format-inapplicable stage. The one exception is Graphviz, which is gated on `R2_RENDER` rather than on the format and keeps its slot in the total either way — see the note under the [phase table](pipelines-and-phases.md#analysis-phases).

Before stage 1 the banner, the file identity, and the hashes are printed unnumbered; after the last stage the run prints a `summary` banner.

### Known PE hashes

For a PE sample the analyzer looks the computed SHA-256 up in `data/known_pe_hashes.jsonl` — the roster of known PE files built from the EMBER2024 Win64 corpus (train, test, and challenge; 216,310 distinct hashes after removing the repeats the corpus files contain). A hit reports the label the corpus recorded, the malware family, and which split the hash came from:

```text
    SHA-256:              6773fee7acd3cd311f68283230834a803f1549f20c338717f283bbeae823dfc3
    TLSH:                 1A343B926ACB4CF...
    Known PE:             yes
      Label:              malicious (EMBER label 1)
      Family:             emotet
      Split:              challenge
      Roster:             216310 hashes (C:\...\data\known_pe_hashes.jsonl)
```

This is a **corpus membership check, not a verdict**. A match means the file is in the reference set and the label is what that set says about it; it is not a fresh judgement about the file in front of you. The roster covers Win64 PEs only, so non-PE samples are never looked up — asking whether an ELF is in a list of PE hashes would be a category error.

The lookup is part of the hash stage rather than a numbered phase of its own, so it adds no `[phase n/total]` work and a run over a sample with no roster installed behaves exactly as before. A missing or unreadable roster is logged and skipped, never reported as an analysis error. Point `KNOWN_PE_HASHES_FILE` at another JSONL to use a different roster; malformed lines are skipped and counted rather than aborting the load. Results are written to `exports/<stem>_analysis/known_pe/<stem>_known_pe.json`, and only when a roster was actually consulted — a file recording `matched: false` for a run that never looked anything up would be indistinguishable from a real negative.

## Safe test fixture

The project retains defensive sample inputs and fixtures under:

```text
tests/fixtures/eicar_ioc_fixture.cpp
```

It is a defensive test input generator containing the standard EICAR antivirus test signature, documentation/reserved domain strings, documentation IP addresses from `TEST-NET` ranges, example URLs, e-mail addresses, and labels intended to exercise IOC and threat-summary paths.

It does **not** contain a real payload, exploit, downloader, persistence mechanism, credential theft, evasion logic, or network client. It is intended to be compiled and passed to the analyzer for extraction/report testing.

Because the source contains EICAR, antivirus software may flag or quarantine the executable. This is expected for an EICAR test fixture.

## Validation

Automated unit and smoke tests have been removed for now. The analyzer's defensive input fixtures remain available for manual verification. Build and syntax-check the Python dashboard tools with:

```powershell
cmake --build --preset ucrt64-release
py -m py_compile python\_create_dashboard.py python\stix_graph.py python\_view_stix.py
```

For a manual end-to-end check, run the analyzer over the included PE fixture:

```powershell
$env:STATIC_ANALYZER_CURSES = "0"; $env:CTI_SKIP = "1"
.\build-ucrt\static_analyzer.exe .\tests\fixtures\suspicious_sample.exe
```

The PE fixture should report **23** stages. `CTI_SKIP=1` keeps the run offline while still exercising the other stages, including STIX and Navigator output.

When changing the dashboard template, regenerate the report and verify that it has no unrendered Jinja markers, valid embedded JSON, working `file://` behavior, expected graph/assembly data, and syntactically valid inline JavaScript.

The STIX viewer has no third-party dependencies — `python/stix_graph.py` and
`python/templates/stix.html` use only the standard library — so it can be checked on its own:

```powershell
py python\_view_stix.py exports\<stem>_analysis\stix\<stem>_stix21.json --navigator
```

## Analysis phases

The stages run in the order below. The number a stage actually prints is assigned at run time to the stages that apply to this file, so a stage's printed number shifts when an earlier stage is skipped — an ELF's "strings + IOC" prints as `[phase 2/20]` where a PE's prints as `[phase 3/23]`.

| Order | Stage | Applies to |
|---:|---|---|
| 1 | Format-specific section analysis (PE, ELF, or Mach-O) | all |
| 2 | Generic section table, virtual addresses, entropy, chi-squared | formats without a dedicated view |
| 3 | String extraction and IOC classification | all |
| 4 | PE import table (IAT) | PE |
| 5 | MalAPI lookups over the imported function names | PE |
| 5b | **YARA rule generation (yarGen-Go)** — opt-in, see [above](#generating-yara-rules-yara_gen) | all |
| 6 | ELF/Mach-O GOT and PLT | ELF, Mach-O |
| 7 | Byte histogram and entropy | all |
| 8 | Packer detection | all |
| 9 | Opcode-byte statistics | all |
| 10 | Debug sections and symbols | all |
| 11 | Authenticode/signature checks | all |
| 12 | capa capability analysis | all |
| 13 | radare2 functions and assembly artifacts | all |
| 14 | Graphviz rendering of call graphs and section CFGs | `R2_RENDER` set (see note) |
| 15 | IAT/GOT call-site assembly and cross-references | all |
| 16 | Compilation guards and mitigation flags | all |
| 17 | Export address table (EAT) | PE |
| 18 | YARA rule scan | PE |
| 19 | xxd hex dump | all |
| 20 | cminer code caves | all |
| 21 | Pipeline error recovery and warnings | all |
| 22 | CTI provider collection and correlation | all |
| 23 | Structured artifact export | all |
| 24 | Self-contained HTML dashboard generation | all |
| 25 | Invalid-input sanity checks | all |

Every stage above except Graphviz is gated on the file format alone. Graphviz is the exception: its slot is still counted in the 25/23/20 total, but the stage returns before printing its header unless `R2_RENDER` is set. On a default run, therefore, the printed numbers skip that slot and the last stage reports one less than the total — `[phase 22/23]` for a PE, `[phase 19/20]` for an ELF or Mach-O. Setting `R2_RENDER` (for example `R2_RENDER=svg`) makes the run fill all of its advertised slots.

The capa phase allows 15 minutes for samples up to 50 MiB and 30 minutes above that; `CAPA_TIMEOUT` and `CAPA_LARGE_TIMEOUT` override either budget in seconds. The cminer code-cave stage scans the PE in-process (section table from LIEF plus a chunked NULL-run scan over the raw bytes) - it needs no external Cminer binary, shell, or WSL.

A stage can be partial when an external dependency, provider, or file feature is missing. The analyzer records warnings and continues where possible; the final result can still be `FAILED` if a required analysis fails.

