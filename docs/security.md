# Security and responsible use

<!-- Source: README.md, split by topic. -->

## Security and responsible use

- Analyze only files you own or have permission to inspect.
- Do not run unknown samples on a normal workstation.
- Use a disposable VM or isolated environment for dynamic testing.
- Treat extracted URLs, domains, and IPs as untrusted data.
- Do not click links from reports automatically.
- Keep CTI keys and logs out of source control.
- Review generated HTML before sharing it because it embeds sample-derived strings and metadata.

## License and repository status

External libraries, rule sets, caches, and vendored data retain their own licenses and notices. Review `.gitignore` and repository status before committing; generated and local files may appear untracked because this working tree may not have a committed Git baseline.

## CTI and network behavior

CTI collection is enabled in the main build through `CTI_WITH_COLLECT`. Providers can perform DNS, RDAP, certificate transparency, IP reputation, vulnerability, or other configured lookups. Provider results are cached under `cache/` and the CTI report is written under `exports/<stem>_analysis/cti/`.

Common configuration categories include API keys, cache directories, proxy/TLS settings, provider enable/disable settings, timeouts, and retries. Use an isolated analysis environment and review provider configuration before enabling external collection. Offline runs represent missing provider data as unknown/skipped rather than fabricating findings.

