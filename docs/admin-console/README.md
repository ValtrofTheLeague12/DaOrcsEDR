# Admin console

<!-- Source: README.md, split by topic. -->

### Admin console (web dashboard)

A React console in `admin-web/`, served by `python/panel/` on `127.0.0.1:60100`.
It is separate from two things it is easy to confuse it with: the
[static-analysis dashboard](../results.md#dashboard) above, which is a per-sample HTML file
written into `exports/`, and the Admin Terminal TUI in `admin-terminal/`. All
three can be running at once and they do not share state.

```powershell
.\admin-panel.ps1              # build the SPA, start the panel, open a browser
.\admin-panel.ps1 -Dev         # Vite on :60101 with HMR, proxying /api to the panel
.\admin-panel.ps1 -NoBrowser   # start without opening a browser
```

The panel binds loopback only and always will — `config.bind_host()` is a
function precisely so that is one obvious place rather than a value someone
changes. Set `ADMIN_WEB_PORT` to move the port and `ADMIN_PANEL_TOKEN` to put a
login in front of it. Every route is introspected into the in-app
**Documentation** page and into `/api/openapi.json`, so the
catalog cannot drift from what the panel actually serves.

