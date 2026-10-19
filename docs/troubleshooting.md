# Troubleshooting

<!-- Source: README.md, split by topic. -->

## Troubleshooting

### Python cannot import Jinja2

The analyzer uses the Python launcher (`py`) by default. Confirm the selected interpreter has Jinja2:

```powershell
py -c "import jinja2; print(jinja2.__version__)"
```

The first `python3` on PATH may not be the interpreter selected by the Windows `py` launcher.

### radare2 output is missing

Check that the configured runner can find radare2. On Windows it may execute through WSL. Confirm the WSL distribution, radare2 installation, and mounted repository path. `bad_output` means valid JSON/DOT was not obtained; it is different from a valid analysis with zero findings.

### Dashboard is stale

The generated HTML is an artifact, not a live view of the source template. After changing `python/templates/dashboard.html.j2` or `python/_create_dashboard.py`, regenerate `exports/<stem>_analysis/dashboard/<stem>.html`.

### Large sample or empty assembly

Assembly is embedded under a configurable size budget. Large assembly JSON can be omitted or truncated while the rest of the report remains available. Increase the budget only when the resulting HTML size is acceptable.

### External providers fail

Provider failures are recorded in the CTI report. Check logs, provider configuration, proxy/TLS settings, API keys, and network policy. A provider failure does not automatically mean the sample analysis failed.

