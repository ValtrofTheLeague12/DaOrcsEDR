# Documentation

The README is the front door; this is the rest of the building. Each file is
one functional area, so you can read the thing you need without scrolling past
eight things you don't.

| Page | What it covers |
| --- | --- |
| [Getting started](getting-started.md) | What the project does, invoking it, running the analyzer, the Python API server |
| [Pipelines and analysis phases](pipelines-and-phases.md) | The phase catalog, format detection, which stages apply to what, validation, the safe test fixture |
| [Evidence bundles, encryption and output](evidence-and-encryption.md) | What gets written, where generated files live, and what happens before anything leaves the machine |
| [Admin console](admin-console/README.md) | The web console at `127.0.0.1:60100` — see below |
| [Qiling analysis VM](qiling-vm.md) | The emulated VM, its rootfs, and the registry/DLL collection workflow |
| [Failure handling and recovery](failure-and-recovery.md) | Exit codes, stopping a run, resuming it, and what a fault prints |
| [Results](results.md) | The HTML dashboard, STIX/ATT&CK output, assembly collection |
| [Building the analyzer](building.md) | Requirements, the build, container images, repository layout, and how to run the tests |
| [Security and responsible use](security.md) | Scope, what the tool will and will not do with a sample, licensing |
| [Troubleshooting](troubleshooting.md) | The failures people actually hit |

## The admin console, in parts

474 lines of the old README were the console alone, which is too long to be
useful as one page.

The console has **two configuration pages**, and which one you want is the whole
question: [Analysis configuration](admin-console/analysis-config.md) is
`config/analysis.yaml` and decides what *every* run does, while
[Pipelines Configuration](admin-console/pipelines-configuration.md) is
`pipelines/*.yaml` and decides what *one kind* of run does. The analyzer applies
the first after the second, so a key may be set in only one of them.

| Page | Covers |
| --- | --- |
| [Overview](admin-console/README.md) | Starting it, binding, auth, the three things it is easy to confuse it with |
| [Networking](admin-console/networking.md) | The live host/adapter/container/VirtualBox graph |
| [Artifacts](admin-console/artifacts.md) | Local and remote evidence bundles, export, recovery |
| [Analysis configuration](admin-console/analysis-config.md) | `config/analysis.yaml` — the settings that apply to every run |
| [Pipelines Configuration](admin-console/pipelines-configuration.md) | `pipelines/*.yaml` - the phase wizard, per-pipeline options, authoring, generating YARA rules |
| [Build identity and tests](admin-console/build.md) | Provenance, freshness, validation, and running tests from the browser |
| [Utils](admin-console/utils.md) | SBOM, MalAPI rules, YARA packs, yarGen-Go maintenance |
| [ClamAV](admin-console/clamd.md) | Service status, sample submission (SFTP or TCP INSTREAM), output logs, scan results |

## Not documented here

- **`unit/README.md`** — what belongs in a unit test, what does not, and how to
  run both suites.
- **`admin-terminal/`** — the TUI. It is a small, self-contained tool with its
  own menu and no configuration surface worth a page here.
- **`CONTAINER-TESTING.md`** — linked from [Building](building.md), but it does
  not exist. That link was already dead before this split; it is left in place
  because inventing a target for it would be worse than a visible dangling
  reference.

## If you are here to do something specific

| I want to… | Go to |
| --- | --- |
| run the analyzer | [Getting started](getting-started.md) |
| change what a run does | [Pipelines](pipelines-and-phases.md), then [Pipelines Configuration](admin-console/pipelines-configuration.md) |
| change what *every* run does | [Analysis configuration](admin-console/analysis-config.md) |
| know whether a binary is current | [Build identity](admin-console/build.md) |
| update a vendored tool | [Utils](admin-console/utils.md) |
| see why a run failed | [Failure handling](failure-and-recovery.md) |
| build it from scratch | [Building](building.md) |
| find out what a phase writes | [Output layout](evidence-and-encryption.md#output-layout) |