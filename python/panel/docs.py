"""Every HTTP endpoint this lab exposes, as one browsable reference.

Three sources, because "documentation" here has to mean *true* documentation:

  * The panel's own routes are INTROSPECTED from the live Flask URL map, not
    written out by hand. A hand-written list drifts the moment someone adds a
    route and forgets to update the docs - which is exactly how the docs become
    a list of lies. Reading app.url_map and pulling each view function's
    docstring means this catalog is correct by construction.

  * The analyzer's capabilities are fetched from the running service when it is
    up, because `/capabilities` is the authority on its own surface. The static
    table below is only a fallback for when it is down, and it is labelled as
    such in the UI.

  * The service probes come from services.overview(), so the reference doubles as
    a liveness sheet: every documented endpoint shows whether it is answering.

Nothing here probes anything new. It reuses the one probe pass the Services
panel already makes, so adding documentation costs no extra connections.
"""

from __future__ import annotations

import ast
import inspect
import ipaddress
import json
import re
import socket
import subprocess

from flask import current_app

from . import config, netinfo, services

# The CyberChef API is the one surface not defined by a file on this disk - it
# is a container image. Its request body is read from the analyzer's own client
# (src/net/cyberchef.cpp), the only thing in the repo that calls it, so these
# keys are what the lab actually sends rather than a guess at CyberChef's
# published schema.
CYBERCHEF_ROUTES = [
    {"method": "GET", "path": "/health", "summary": "Healthcheck target used by compose",
     "params": {"path": [], "query": [], "form": [], "body": None}},
    {"method": "POST", "path": "/bake", "summary": "Run a CyberChef recipe over a string",
     "params": {"path": [], "query": [], "form": [], "body": "JSON body",
                "fields": ["input", "recipe"]}},
    {"method": "POST", "path": "/magic", "summary": "Identify a string; proposes a recipe",
     "params": {"path": [], "query": [], "form": [], "body": "JSON body",
                "fields": ["input"]}},
]

# Where each service keeps its routes, relative to the repo root.
_SOURCES = {
    "analyzer": "server.py",
    "malapi": "python/api/server.py",
    "ml": "ml/serve.py",
}

# Summaries for routes whose handler has no docstring to lift.
#
# ml/serve.py's view functions are bare `return jsonify(...)` with no docstrings,
# so an honest parse yields five blank rows - technically complete and useless to
# read. These are editorial, written here from what the handler returns, and
# flagged `source: "editorial"` in the payload so the UI can show that they came
# from here rather than from the code.
_ROUTE_NOTES = {
    "ml:GET /health": "Liveness plus the model's identity and metrics",
    "ml:GET /model": "Model card: features, training metrics and version",
    "ml:POST /score": "Score a PE file; returns the malicious probability",
    "ml:POST /score/vector": "Score an already-extracted feature vector",
    "ml:POST /score/batch": "Score many vectors in one call",
    "cyberchef:GET /health": "Healthcheck target used by compose",
    "cyberchef:POST /bake": "Run a CyberChef recipe over a file",
    "cyberchef:POST /magic": "Identify file type from magic bytes",
}


def _annotate(service: str, routes: list[dict]) -> list[dict]:
    """Fill blank summaries from the editorial table and record provenance."""
    for r in routes:
        note = _ROUTE_NOTES.get(f"{service}:{r['method']} {r['path']}")
        if note:
            r["summary"] = note
            r["source"] = "editorial"
        else:
            r["source"] = "code"
    return routes


def _first_line(doc: str | None) -> str:
    """The summary line of a docstring - the rest is an argument example."""
    if not doc:
        return ""
    for line in doc.strip().splitlines():
        text = line.strip()
        if text:
            return text
    return ""


# ---------------------------------------------------------------------------
# Reading routes out of another service's source
#
# The panel introspects its OWN routes from the live URL map. The other services
# are separate processes, so their URL map is not reachable - but their SOURCE
# is, and it is the thing that defines their routes.
#
# Parsing with `ast` rather than regex matters here: the files use stacked and
# aliased decorators, f-strings and dict literals, and a regex over those
# produces confidently wrong results. ast gives the literal route string and
# the function's own docstring, which is exactly what a reference needs.
#
# The payoff is that the same drift problem is solved for all of them: add a
# route to ml/serve.py and it appears here with no second edit.
# ---------------------------------------------------------------------------

_SOURCE_CACHE: dict[str, list[dict]] = {}

_DECORATORS = {"get", "post", "put", "patch", "delete"}


def _literal(node: ast.AST) -> str | None:
    """The value of a plain string literal, or None if it is computed."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _handler_params(node) -> dict:
    """What one view function actually reads off the request.

    Walked from the AST rather than declared by hand, because the parameters a
    route takes live in `request.args.get("lines")` inside the handler - there is
    no other place to look, and transcribing them is exactly the drift problem
    this whole module exists to avoid.
    """
    out = {"path": [], "query": [], "form": [], "body": None, "view_args": False}

    def add(bucket: str, name: str) -> None:
        if name and name not in out[bucket]:
            out[bucket].append(name)

    for sub in ast.walk(node):
        # request.args.get("x") / request.form.get("x")
        if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                and sub.func.attr == "get" and sub.args):
            owner = sub.func.value
            bucket = None
            if isinstance(owner, ast.Attribute) and isinstance(owner.value, ast.Name):
                if owner.value.id == "request" and owner.attr == "args":
                    bucket = "query"
                elif owner.value.id == "request" and owner.attr == "form":
                    bucket = "form"
            if bucket and isinstance(sub.args[0], ast.Constant) \
                    and isinstance(sub.args[0].value, str):
                add(bucket, sub.args[0].value)

        # request.view_args  -> the handler reads path parameters
        elif isinstance(sub, ast.Attribute) and sub.attr == "view_args" \
                and isinstance(sub.value, ast.Name) and sub.value.id == "request":
            out["view_args"] = True

        # request.get_json(...) -> the body is a JSON document, so its shape is
        # the handler's business; say a body is expected rather than guessing keys.
        elif (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
              and sub.func.attr == "get_json"
              and isinstance(sub.func.value, ast.Name)
              and sub.func.value.id == "request"):
            out["body"] = "JSON body"

        # request.data / request.files -> a raw or multipart body
        elif isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) \
                and sub.value.id == "request" and sub.attr in ("data", "files"):
            out["body"] = out["body"] or "request body"

    return out


def _path_params(rule: str) -> list[str]:
    """Names of the <converter:name> placeholders in a Flask rule."""
    return re.findall(r"<(?:[^:<>]+:)?([^<>]+)>", rule)


def _routes_from_source(rel_path: str) -> list[dict]:
    """Every Flask route declared in a source file, with its docstring summary."""
    if rel_path in _SOURCE_CACHE:
        return _SOURCE_CACHE[rel_path]

    path = config.REPO / rel_path
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        _SOURCE_CACHE[rel_path] = []
        return []

    out: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        summary = _first_line(ast.get_docstring(node))
        for dec in node.decorator_list:
            # @app.get("/x") / @app.route("/x", methods=["POST"])
            if not isinstance(dec, ast.Call):
                continue
            func = dec.func
            if not isinstance(func, ast.Attribute):
                continue
            attr = func.attr
            if attr not in _DECORATORS and attr != "route":
                continue
            if not dec.args:
                continue
            route = _literal(dec.args[0])
            if not route:
                continue
            methods = [attr.upper()] if attr != "route" else None
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = [
                        str(e.value) for e in kw.value.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)
                    ]
            for method in (methods or ["GET"]):
                if method == "HEAD":
                    continue
                params = _handler_params(node)
                out.append({
                    "method": method,
                    "path": route,
                    "summary": summary,
                    "handler": node.name,
                    "line": node.lineno,
                    "params": {
                        **params,
                        "path": _path_params(route),
                    },
                })

    # Drop duplicates from stacked decorators on one function.
    seen: set[tuple[str, str]] = set()
    unique: list[dict] = []
    for r in out:
        key = (r["method"], r["path"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(r)

    unique.sort(key=lambda r: (r["path"], r["method"]))
    _SOURCE_CACHE[rel_path] = unique
    return unique


def _capability_aliases(rel_path: str) -> list[dict]:
    """The analyzer's short POST aliases, derived from its CAPABILITIES dict.

    server.py registers these in a loop with `app.add_url_rule(f"/{cap}", ...)`,
    so they are invisible to a decorator scan and to the panel's own URL map. The
    dict literal that drives the loop is right there in the module, so it is
    parsed rather than transcribed.
    """
    path = config.REPO / rel_path
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError, ValueError):
        return []

    names: list[str] = []
    for node in ast.walk(tree):
        # `CAPABILITIES: dict[...] = {...}` is an AnnAssign, not an Assign -
        # missing that is how the aliases silently came back empty.
        if isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        elif isinstance(node, ast.Assign):
            target = node.targets[0] if node.targets else None
            value = node.value
        else:
            continue
        if not isinstance(target, ast.Name) or target.id != "CAPABILITIES":
            continue
        if isinstance(value, ast.Dict):
            names = [
                str(k.value) for k in value.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            ]
    return [
        {
            "method": "POST",
            "path": f"/{name}",
            "summary": f"Short alias for POST /capabilities/{name}",
            "handler": "capability alias (add_url_rule loop)",
            "line": 0,
        }
        for name in names
    ]


def _live_spec(base: str, timeout: float = 1.5) -> tuple[dict | None, str | None]:
    """Ask a running service to document itself.

    Preferred over parsing its source: the service is the authority on its own
    surface, and a live OpenAPI document cannot drift from the code the way a
    transcription can. Returns (paths_from_spec, error).

    Only the analyzer and the ML scorer are attempted - they are ours to
    instrument. MalAPI is generated code and CyberChef is a container image, so
    for those the parsed source is the only option available.
    """
    import urllib.request

    url = base.rstrip("/") + "/apispec_1.json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read(4 * 1024 * 1024).decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001 - down, slow or absent is normal
        return None, f"{type(exc).__name__}: {exc}"
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return None, "spec was not an OpenAPI document"
    return data["paths"], None


def _routes_from_spec(paths: dict, service: str) -> list[dict]:
    """Flatten an OpenAPI paths object back into docs.py's route shape."""
    out: list[dict] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        # Strip the per-service prefix this panel added when merging, if present.
        clean = path[len(service) + 1:] if path.startswith(f"/{service}/") else path
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if not isinstance(op, dict):
                continue
            params = {"path": [], "query": [], "form": [], "body": None}
            for p in op.get("parameters") or []:
                if not isinstance(p, dict):
                    continue
                where = str(p.get("in") or "").lower()
                name = str(p.get("name") or "")
                if where in ("path", "query", "formdata"):
                    params[where].append(name)
                elif where == "body":
                    params["body"] = "JSON body"
            out.append({
                "method": method.upper(),
                "path": clean,
                "summary": str(op.get("summary") or ""),
                "description": str(op.get("description") or "").strip() or None,
                "handler": op.get("operationId"),
                "params": params,
                "source": "live-spec",
            })
    out.sort(key=lambda r: (r["path"], r["method"]))
    return out
    """Collapse a large route family into one pattern + count.

    MalAPI declares ~550 routes that differ only by name
    (/malapi/CreateProcessA/ and 500 siblings). Listing them all is technically
    complete and practically useless, so the family is summarised and the count
    is kept - the UI still offers the full list to search.
    """
    matched = [r for r in routes if r["path"].startswith(prefix)]
    if not matched:
        return []
    sample = max(matched, key=lambda r: len(r["path"]))
    dynamic = "<" in sample["path"]
    return [{
        "method": "GET" if all(r["method"] == "GET" for r in matched) else "MIXED",
        "path": prefix + ("/<name>/" if dynamic and not prefix.endswith("/") else ""),
        "summary": (
            f"{len(matched)} routes, one per entry - see the searchable list below. "
            f"Pattern: {prefix}<name>"
        ),
        "handler": f"{len(matched)} declarations",
        "line": 0,
        "count": len(matched),
        "family": True,
    }]


# ---------------------------------------------------------------------------
# IP + port facts
#
# Every service here answers on a literal address, so the panel can say what
# that address actually IS rather than leaving the admin to work it out: is
# 192.168.56.105 on a /24, is it routable, and is 9092 a registered port or one
# this lab made up.
#
# Everything below is derived from the address itself, never guessed from a
# naming convention, and anything that cannot be determined is None rather than
# a plausible-looking default.
# {handler function name: params} for this panel's own app.py, so the live URL
# map can be enriched with the arguments each view actually reads. Filled at
# import time - the file is small and this runs once.
_PANEL_PARAMS: dict[str, dict] = {}


def _load_panel_params() -> None:
    try:
        tree = ast.parse(
            (config.REPO / "python" / "panel" / "app.py").read_text(
                encoding="utf-8", errors="replace"
            )
        )
    except (OSError, SyntaxError, ValueError):
        return
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = _handler_params(node)
        if any((params["path"], params["query"], params["form"])) or params["body"]:
            _PANEL_PARAMS[node.name] = params


_load_panel_params()


def _panel_routes(app=None) -> tuple[list[dict], list[str]]:
    """Introspect the running app's URL map.

    `current_app` is used deliberately: the catalog is derived from the routes
    actually registered, so it cannot describe a route that was deleted or miss
    one that was added. Returns (api_routes, spa_shell_paths).
    """
    app = app or current_app
    rules = getattr(app, "url_map", None)
    if rules is None:  # pragma: no cover - only outside a request context
        return [], []

    out: list[dict] = []
    shell: list[str] = []
    for rule in rules.iter_rules():
        if rule.endpoint == "static":
            continue
        view = app.view_functions.get(rule.endpoint)
        summary = _first_line(inspect.getdoc(view) if view else None)
        methods = sorted(
            (rule.methods or set()) - {"HEAD", "OPTIONS"},
            key=lambda m: {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}.get(m, 4),
        )
        # admin_server.py registers a catch-all that serves the React bundle for
        # any non-/api path. Those are not API endpoints - listing "/<path:path>"
        # in an API reference is noise - but they are collected rather than
        # silently dropped, so the UI can say the bundle is served there.
        if not str(rule.rule).startswith("/api"):
            shell.append(str(rule.rule))
            continue
        for method in methods:
            pp = dict(_PANEL_PARAMS.get(rule.endpoint) or {
                "query": [], "form": [], "body": None, "view_args": False,
            })
            # Path placeholders come from the live rule, which is authoritative.
            pp["path"] = _path_params(str(rule.rule))
            out.append({
                "method": method,
                "path": str(rule.rule),
                "summary": summary,
                "endpoint": rule.endpoint,
                # Safe to hand to the browser only for reads: a POST here would
                # start a rootfs build or stop a container.
                "safe_get": method == "GET",
                "params": pp,
            })

    out.sort(key=lambda r: (r["path"], r["method"]))
    return out, sorted(set(shell))


def _analyzer_capabilities(overview: dict | None) -> tuple[list[dict], bool]:
    """The analyzer's own capability list, fetched live when it is up.

    Returns (capabilities, from_live_service). The analyzer is the authority on
    its own surface, so when it answers we believe it rather than our copy.
    """
    base = f"http://{config.analyzer_base()}"
    try:
        import json
        import urllib.request

        req = urllib.request.Request(base + "/capabilities", method="GET")
        with urllib.request.urlopen(req, timeout=config.PANEL_TIMEOUT) as resp:
            data = json.loads(resp.read(65536).decode("utf-8", "replace"))
        if isinstance(data, list) and data:
            return [
                {
                    "name": str(c.get("name") or ""),
                    "summary": str(c.get("description") or ""),
                    "phases": [str(p) for p in (c.get("phases") or [])],
                    "endpoint": str(c.get("endpoint") or ""),
                    "alias": str(c.get("alias") or ""),
                }
                for c in data
                if isinstance(c, dict)
            ], True
    except Exception:  # noqa: BLE001 - down or slow is the normal case here
        pass

    if overview is None:
        return [], False
    # Fall back to our own transcription, clearly marked as not live.
    return [
        {
            "name": "hashes", "summary": "SHA-256/MD5/SHA1 + file info",
            "phases": ["export"], "endpoint": "/capabilities/hashes", "alias": "/hashes",
        },
        {
            "name": "strings", "summary": "extracted strings + CyberChef decode pass",
            "phases": ["strings"], "endpoint": "/capabilities/strings", "alias": "/strings",
        },
        {
            "name": "capa", "summary": "capa capability detection",
            "phases": ["capa"], "endpoint": "/capabilities/capa", "alias": "/capa",
        },
        {
            "name": "model", "summary": "EMBER2024 LightGBM score (needs the ML service)",
            "phases": ["model"], "endpoint": "/capabilities/model", "alias": "/model",
        },
    ], False


FAMILY_DOCS = {
    "/malapi/": (
        "Windows API classification",
        "One endpoint per Windows API. Substitute the name in the path: "
        "`/malapi/CreateProcessA/`, `/malapi/AdjustTokenPrivileges/`. Returns "
        "the YAML record for that call - how malicious it is considered and "
        "why. The full list of names lives in the panel's Documentation page, "
        "where it is searchable; listing all of them here would bury every "
        "other endpoint in the lab.",
    ),
    "/lolbas/domain/": (
        "Living-off-the-land sites",
        "One endpoint per domain. Substitute the name in the path: "
        "`/lolbas/domain/pastebin.com`, `/lolbas/domain/raw.githubusercontent.com`. "
        "Returns the record for that site - what it is used for and why an "
        "executable calling it is interesting. Searchable in the panel's "
        "Documentation page.",
    ),
}


def _collapsed(routes: list[dict]) -> list[dict]:
    """Replace each generated family with a single pattern entry.

    MalAPI declares ~550 routes that differ only by name. In a Swagger UI that
    is 550 near-identical rows and a page nobody scrolls - so each family
    becomes one documented pattern, and the real names stay searchable in the
    panel's own Documentation list.
    """
    out: list[dict] = []
    for prefix, (title, blurb) in FAMILY_DOCS.items():
        members = [r for r in routes if r["path"].startswith(prefix)]
        if not members:
            continue
        names = [r["path"].split(prefix, 1)[1].rstrip("/") for r in members]
        sample = names[0] if names else "name"
        out.append({
            "method": "GET",
            "path": prefix + "{name}",
            "summary": f"{title} ({len(members)} routes)",
            "description": blurb,
            "handler": f"{len(members)} generated declarations",
            "params": {
                "path": [], "query": [], "form": [], "body": None,
                # Expressed as an OpenAPI path parameter directly, since the
                # whole point of the entry IS the placeholder.
                "fields": [],
            },
            "family_count": len(members),
            "family_sample": sample,
        })
    out.extend(r for r in routes if not r["path"].startswith(tuple(FAMILY_DOCS)))
    return out


def openapi_doc(app=None) -> dict:
    """One OpenAPI 3.0 document covering EVERY service in the lab.

    flasgger on its own only describes the app it is attached to - the panel -
    which left the analyzer, ML, MalAPI and CyberChef invisible in the Swagger
    UI. Rather than bolt flasgger onto four more apps (two of which cannot be
    touched: the analyzer's app is built inside a factory, and MalAPI's 547
    routes are generated), the catalogue is rendered as a single merged spec
    here and handed to the same UI.

    Two things make a merged document work:

      * Paths are prefixed per service (`/analyzer/health`). Four of the five
        services expose a GET /health, and OpenAPI keys paths uniquely, so an
        unprefixed merge would silently lose three of them.

      * Each operation carries its own `servers`, so "Try it out" still posts to
        the right base URL even though the path prefix is not a real route.

    The prefixed path never appears as something to call - the original is in
    the description - because Swagger UI builds the request from server + path.
    """
    cat = catalog(app)
    order = ["panel", "analyzer", "malapi", "ml", "cyberchef"]

    tags = []
    paths: dict[str, dict] = {}

    for key in order:
        svc = cat.get(key) or {}
        base = svc.get("base") or ""
        routes = svc.get("routes") or []
        # Generated families collapse to one pattern each - see _collapsed().
        if key == "malapi":
            routes = _collapsed(routes)
        tags.append({
            "name": key,
            "description": svc.get("source") or "",
            "x-base-url": base,
        })

        for r in routes:
            method = str(r.get("method") or "GET").lower()
            if method not in ("get", "post", "put", "patch", "delete"):
                continue
            raw_path = str(r.get("path") or "")
            if not raw_path:
                continue
            # OpenAPI wants {placeholder} braces; Flask uses <angle> brackets.
            spec_path = re.sub(r"<(?:[^:<>]+:)?([^<>]+)>", r"{\1}", raw_path)
            full = f"/{key}{spec_path}"
            op: dict = {
                "summary": r.get("summary") or "",
                "operationId": f"{key}_{method}_{re.sub(r'[^A-Za-z0-9]+', '_', raw_path).strip('_')}",
                "tags": [key],
                "servers": [{"url": base}],
                "responses": {"200": {"description": "Success"}},
            }
            if r.get("description") or r.get("source") == "editorial":
                op["description"] = r.get("description") or "Description written for this panel."

            params = _openapi_params(r)
            if params:
                op["parameters"] = params
            # The unprefixed path is the one that actually exists.
            op.setdefault("description", "")
            op["description"] = (
                (op["description"] + "\n\n" if op["description"] else "")
                + f"`{r.get('method', 'GET')} {base}{raw_path}`"
                + (f"  \nHandler: `{r['handler']}`" if r.get("handler") else "")
            )

            paths.setdefault(full, {})[method] = op

    return {
        "openapi": "3.0.3",
        "info": {
            "title": "IAProject lab API",
            "version": "1.0",
            "description": (
                "Every HTTP surface in the lab, in one document. Paths are "
                "prefixed by the service that owns them; each operation lists "
                "the real base URL under Servers, which is what Try it out "
                "posts to. Routes are introspected from the panel's live URL map "
                "and parsed from each service's source, so this cannot document "
                "a route that was deleted or miss one that was added."
            ),
        },
        "servers": [{"url": "http://127.0.0.1", "description": "loopback"}],
        "tags": tags,
        "paths": dict(sorted(paths.items())),
    }


def _openapi_params(r: dict) -> list[dict]:
    """Route parameters as OpenAPI parameter objects."""
    p = r.get("params") or {}
    out: list[dict] = []
    # A collapsed family entry is nothing but its placeholder.
    if r.get("family_count"):
        out.append({
            "name": "name",
            "in": "path",
            "required": True,
            "schema": {"type": "string"},
            "description": f"One of {r['family_count']} names, e.g. `{r.get('family_sample')}`",
            "x-family-count": r["family_count"],
        })
        return out
    for name in p.get("path") or []:
        out.append({"name": name, "in": "path", "required": True,
                    "schema": {"type": "string"}})
    for name in p.get("query") or []:
        out.append({"name": name, "in": "query", "required": False,
                    "schema": {"type": "string"}})
    for name in p.get("form") or []:
        out.append({"name": name, "in": "formData", "required": False,
                    "schema": {"type": "string"}})
    for name in p.get("fields") or []:
        out.append({"name": name, "in": "body", "required": False,
                    "schema": {"type": "object"}})
    return out


def _service_routes(key: str, base: str, fallback: list[dict]) -> tuple[list[dict], str]:
    """A service's routes from its own OpenAPI document when it is running,
    otherwise from this panel's parse of its source.

    Returns (routes, provenance). The live spec always wins: a service is the
    authority on its own surface, so there is no reason to prefer our reading of
    its source over what it publishes about itself.
    """
    paths, err = _live_spec(base)
    if paths is not None:
        routes = _routes_from_spec(paths, key)
        if routes:
            return routes, "live OpenAPI spec from the running service"
    return fallback, f"parsed from {_SOURCES[key]}"


def catalog(app=None) -> dict:
    overview = None
    try:
        overview = services.overview()
    except Exception:  # noqa: BLE001 - docs must render even if probing fails
        overview = None

    caps, caps_live = _analyzer_capabilities(overview)
    probes = {p["key"]: p for p in (overview or {}).get("services", [])}
    panel_routes, spa_shell = _panel_routes(app)

    # Analyzer: parsed from server.py, plus the loop-registered POST aliases that
    # a decorator scan cannot see.
    analyzer_routes = _routes_from_source(_SOURCES["analyzer"]) + _capability_aliases(_SOURCES["analyzer"])

    # MalAPI: ~550 routes in two big families. The full list is sent ONCE and the
    # collapsed families are marked by a flag on each row, rather than also
    # shipping a separate `routes` list - sending the same 547 objects twice was
    # most of a 122 KB payload for no benefit.
    malapi_all = _annotate("malapi", sorted(
        _routes_from_source(_SOURCES["malapi"]), key=lambda r: r["path"]))
    # Mark the rows that belong to a generated family so the UI can collapse
    # them. Matched with startswith, not equality: the family pattern is
    # "/malapi/<name>/" while the real rows are "/malapi/Accept/", so comparing
    # against the pattern would have marked nothing and silently shown all 547.
    family_prefixes = ("/malapi/", "/lolbas/domain/")
    for r in malapi_all:
        r["family"] = r["path"].startswith(family_prefixes)

    ml_routes = _annotate("ml", _routes_from_source(_SOURCES["ml"]))
    cyberchef_routes = _annotate("cyberchef", [dict(r) for r in CYBERCHEF_ROUTES])

    # The analyzer and MalAPI do have docstrings on their handlers, so they are
    # annotated too - that call is a no-op for them but keeps the provenance
    # field ("code" vs "editorial") present on every row in the UI.
    analyzer_routes = _annotate("analyzer", analyzer_routes)

    # Ask the running service to document itself; fall back to our parse.
    # Both are in the payload so the UI can say which one it is showing.
    analyzer_final, analyzer_src = _service_routes(
        "analyzer", f"http://{config.analyzer_base()}", analyzer_routes)
    ml_final, ml_src = _service_routes(
        "ml", f"http://{config.ml_base()}", ml_routes)

    def up(key: str) -> bool:
        return bool(probes.get(key, {}).get("up"))

    return {
        "panel": {
            "base": f"http://{config.bind_host()}:{config.panel_port()}",
            "routes": panel_routes,
            "spa_shell": spa_shell,
            "count": len(panel_routes),
            "source": "live Flask URL map",
            "up": True,
        },
        "analyzer": {
            "base": f"http://{config.analyzer_base()}",
            "routes": analyzer_final,
            "capabilities": caps,
            "capabilities_live": caps_live,
            "count": len(analyzer_final),
            "source": analyzer_src,
            "up": up("analyzer"),
        },
        "malapi": {
            "base": f"http://{config.malapi_base()}",
            "routes": malapi_all,
            "count": len(malapi_all),
            "source": f"parsed from {_SOURCES['malapi']}",
            "up": up("malapi"),
        },
        "ml": {
            "base": f"http://{config.ml_base()}",
            "routes": ml_final,
            "count": len(ml_final),
            "source": ml_src,
            "up": up("ml"),
            "auth": bool(config.ml_token()),
        },
        "cyberchef": {
            "base": f"http://127.0.0.1:{config.cyberchef_port()}",
            "routes": cyberchef_routes,
            "count": len(cyberchef_routes),
            "source": "compose.yaml (container image, not a source file here)",
            "up": up("cyberchef"),
        },
        "services": [
            {
                "key": p["key"],
                "name": p["name"],
                "description": p["description"],
                "endpoint": p["endpoint"],
                "host": p["host"],
                "port": p["port"],
                "scheme": p["scheme"],
                "kind": p["kind"],
                "role": p["role"],
                "up": p["up"],
                "code": p["code"],
                "ms": p["ms"],
                "net": netinfo.network_facts(p["host"], p["port"]),
            }
            for p in (overview or {}).get("services", [])
        ],
        "bases": {
            "panel": True,
            "analyzer": up("analyzer"),
            "malapi": up("malapi"),
            "ml": up("ml"),
            "cyberchef": up("cyberchef"),
        },
    }
