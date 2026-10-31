"""Admin orchestration panel.

Proxy and control surface over services that already run in this repo:
the static analyzer REST API, the ML scorer, MalAPI, the compose stacks, and
the analysis VM. It re-implements nothing.

    python python/admin_server.py
    python python/admin_server.py --port 60110

Binds 127.0.0.1 only. The React front end is served from admin-web/dist once
that has been built; before then the API is still fully usable and the UI can
be run from the Vite dev server, which proxies /api here.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from flask import Response, jsonify

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from panel import config  # noqa: E402
from panel.app import create_app  # noqa: E402

DIST = config.REPO / "admin-web" / "dist"


def _serve_spa(app, dist: Path) -> None:
    """Serve the built React app, with client-side routing falling back to
    index.html so a deep link does not 404."""
    if dist.is_dir():
        app.static_folder = str(dist)
        app.static_url_path = "/"

        @app.get("/", defaults={"path": ""})
        @app.get("/<path:path>")
        def spa(path: str):
            if path.startswith("api/"):
                return jsonify(error="not found", path=path), 404
            candidate = (dist / path).resolve()
            # is_relative_to keeps a crafted path from escaping dist/.
            if path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
                return app.send_static_file(path)

            # A rebuild empties dist/ and replaces every hashed chunk. A tab
            # opened before that rebuild still holds the old entry module, so
            # clicking a panel that had not been loaded yet asks for a filename
            # that no longer exists. The generic SPA fallback used to answer
            # with index.html, and the browser then refused to evaluate HTML as
            # a module - "This panel failed to open" until a manual reload.
            #
            # Answer a missing JS chunk with a module that reloads the tab
            # once. The reload fetches the new index, which names the chunks
            # that do exist, so the panel click works instead of failing.
            if path.startswith("assets/") and path.endswith(".js"):
                return Response(
                    "try{const k='ia:stale-chunk';"
                    "const t=Number(sessionStorage.getItem(k)||0);"
                    "if(Date.now()-t>5000){sessionStorage.setItem(k,String(Date.now()));"
                    "window.location.reload();}}catch(e){window.location.reload();}",
                    mimetype="text/javascript",
                    headers={"Cache-Control": "no-store"},
                )
            return app.send_static_file("index.html")

        print(f"[+] serving React UI from {dist}")
    else:
        @app.get("/")
        def missing_ui():
            return jsonify(
                error="React UI not built",
                detail=f"{dist} does not exist. Run: cd admin-web && npm install && npm run build",
            ), 503


def main() -> int:
    ap = argparse.ArgumentParser(description="Admin orchestration panel")
    ap.add_argument("--port", type=int, default=config.panel_port(),
                    help="panel port (default: ADMIN_WEB_PORT or 60100)")
    ap.add_argument("--no-ui", action="store_true",
                    help="API only; do not serve admin-web/dist")
    args = ap.parse_args()

    app = create_app()
    if not args.no_ui:
        _serve_spa(app, DIST)

    host = config.bind_host()
    print(f"[+] panel on http://{host}:{args.port}")
    print(f"[+] repo {config.REPO}")
    # threaded=True because every /api call is a network round trip to another
    # local service; a single-threaded dev server would serialise the page.
    app.run(host=host, port=args.port, debug=False, threaded=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())