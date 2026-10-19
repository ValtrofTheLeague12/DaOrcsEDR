"""Admin orchestration panel - Flask app factory.

A thin proxy in front of services that already exist. It re-implements no
analysis logic and duplicates no probe: every endpoint either forwards to a
real service API or reads a real artefact.

Binding is loopback-only by construction (config.bind_host()). There is no
flag to widen it.

Every view carries an OpenAPI docstring (prose summary, then a `---` YAML
block). That YAML is the only thing flasgger turns into /apispec_1.json, so it
is the contract for these routes and belongs here rather than in a spec file
that could drift away from the code.
"""

from __future__ import annotations

import subprocess
import sys

import yaml
from flask import Flask, jsonify, make_response, request, send_file

from . import (analysis, analysis_settings, artifacts, auth, build,
               build_checks, clamd, config, containers, docs, logs, netmap,
               qiling, services, stats, system, trace, utils, vms, vmmetrics)
from .yamlview import jsonable as _jsonable, spans as _yaml_spans

try:
    from flasgger import Swagger
except ImportError:  # pragma: no cover - optional; the panel still runs without it
    Swagger = None

# Endpoints that must stay reachable without a session, or the UI can never log
# itself in.
_PUBLIC = {"/api/health", "/api/auth/state", "/api/auth/login"}


def create_app() -> Flask:
    app = Flask(__name__)

    # OpenAPI, generated from the LIVE url map rather than from a hand-written
    # spec, so it cannot describe a route that was deleted or miss one that was
    # added. Summaries and parameters come from each view's docstring.
    #
    # `headers` must be an empty list rather than absent: flasgger iterates it
    # in an after_request hook on every response, and a missing key turns every
    # route on the panel into a 500.
    #
    # The Swagger UI template pulls its assets from a CDN, which renders a
    # blank page on an isolated network. /apispec_1.json is unaffected and stays
    # the machine-readable source of truth.
    if Swagger is not None:
        _swagger = Swagger(
            app,
            config={
                "title": "Admin orchestration panel",
                "version": "1.0",
                "description": (
                    "Read-only control surface over the services in this lab. "
                    "Loopback-only; every route below is introspected from the "
                    "running application."
                ),
                "headers": [],
                "specs": [
                    {
                        "endpoint": "apispec_1",
                        "route": "/apispec_1.json",
                        "rule_filter": lambda rule: True,
                        "model_filter": lambda tag: True,
                    }
                ],
                "swagger_ui": True,
                "specs_route": "/apidocs/",
                "static_url_path": "/flasgger_static",
            },
        )

    # The spec flasgger serves is replaced with the merged document covering
    # every service in the lab, because flasgger on its own only describes the
    # app it is attached to - which left the analyzer, ML, MalAPI and CyberChef
    # invisible in the UI.
    #
    # Built here, on demand, rather than at startup: building it probes every
    # service, and doing that during create_app() would add ~7s to boot for a
    # document most sessions never ask for. flasgger caches into
    # `swagger.apispecs` and returns that cache, so seeding it is enough for the
    # UI (whose template fetches /apispec_1.json) to render the merged doc.
    @app.before_request
    def _seed_merged_spec():
        if Swagger is None:
            return None
        if request.path not in ("/apispec_1.json", "/api/openapi.json"):
            return None
        try:
            merged = docs.openapi_doc(app)
        except Exception:  # noqa: BLE001 - fall back to flasgger's own spec
            return None
        _swagger.apispecs["apispec_1"] = merged
        return None

    @app.get("/api/openapi.json")
    def openapi_spec():
        """Merged OpenAPI 3.0 document for every service in the lab
        ---
        tags: [documentation]
        responses:
          200:
            description: One OpenAPI document covering all five HTTP surfaces

        Paths are prefixed per service and each operation carries the real base
        URL under Servers, so Try it out posts to the right place. MalAPI's 547
        generated routes collapse to two documented patterns; the full list is
        searchable in this panel's Documentation page.
        """
        return jsonify(docs.openapi_doc(app))

    @app.before_request
    def _gate():
        if not auth.required():
            return None
        # Only /api/* is gated. The SPA shell and its assets must stay public
        # or a browser cannot load the bundle, and so can never reach the login
        # page that would let it authenticate - a deadlock. The shell is static
        # HTML/JS; it contains no data and nothing worth protecting.
        if not request.path.startswith("/api/"):
            return None
        if request.path in _PUBLIC:
            return None
        # No loopback exemption here, deliberately - unlike ml/serve.py.
        # ml/serve.py is a dependency the analyzer dials without a header, so it
        # has to trust loopback. The panel is only ever driven by a human
        # browser, and a loopback bypass would mean setting ADMIN_PANEL_TOKEN
        # does nothing locally: the login page would never appear and the token
        # would look like it worked while gating nothing. Either it gates or it
        # does not exist.
        ok = auth.authorised(
            request.cookies.get(auth.COOKIE_NAME),
            (request.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
            or None,
            request.remote_addr,
        )
        if ok:
            return None
        return jsonify(error="unauthorised",
                       detail="POST the token to /api/auth/login"), 401

    # --- auth --------------------------------------------------------------

    @app.get("/api/auth/state")
    def auth_state():
        """Whether This Panel Is Gated, and Whether the Caller Is Through
        ---
        tags: [auth]
        responses:
          200:
            description: Current authentication state"""
        return jsonify({
            "required": auth.required(),
            "authorised": auth.authorised(
                request.cookies.get(auth.COOKIE_NAME),
                None,
                request.remote_addr,
            ),
            "loopback": auth.is_loopback(request.remote_addr),
        })

    @app.post("/api/auth/login")
    def login():
        """Exchange the Panel Token for a Session Cookie
        ---
        tags: [auth]
        parameters:
          - name: body
            in: body
            required: true
            schema:
              type: object
              properties:
                token:
                  type: string
            description: JSON object with a token field
        responses:
          200:
            description: Session cookie issued
          401:
            description: Bad token"""
        body = request.get_json(silent=True) or {}
        candidate = body.get("token") or ""
        if not auth.check_token(candidate):
            return jsonify(error="unauthorised", detail="bad token"), 401
        resp = make_response(jsonify(ok=True))
        resp.set_cookie(
            auth.COOKIE_NAME, auth.issue_cookie(),
            httponly=True,     # not readable from JS, so an XSS cannot exfiltrate it
            samesite="Strict", # no cross-site submission
            secure=False,      # the panel is plain HTTP on loopback; see auth.py
            max_age=auth.SESSION_TTL,
            path="/",
        )
        return resp

    @app.post("/api/auth/logout")
    def logout():
        """Drop the Session Cookie
        ---
        tags: [auth]
        responses:
          200:
            description: Cookie cleared"""
        resp = make_response(jsonify(ok=True))
        resp.delete_cookie(auth.COOKIE_NAME, path="/")
        return resp

    # --- panel -------------------------------------------------------------

    @app.get("/api/health")
    def health():
        """Liveness, and the Address This Panel Is Bound To
        ---
        tags: [panel]
        responses:
          200:
            description: Panel is up"""
        return jsonify(status="ok", panel="admin", bind=config.bind_host())

    @app.get("/api/overview")
    def overview():
        """Live Probe of Every Registered Service
        ---
        tags: [services]
        responses:
          200:
            description: Per-service up/down, latency and resolved endpoints"""
        return jsonify(services.overview())

    @app.get("/api/system")
    def system_info():
        """Host CPU, Memory, GPU, Disks and Top Processes
        ---
        tags: [machine]
        responses:
          200:
            description: Current machine state with a sampled history"""
        return jsonify(system.info())

    @app.get("/api/stats")
    def statistics():
        """Aggregated Statistics Across Every Concern
        ---
        tags: [machine]
        responses:
          200:
            description: Services, machine, logs, runs and containers combined"""
        # Gated like every other api route; the shell is the only public path.
        return jsonify(stats.snapshot())

    @app.get("/api/logs")
    def list_logs():
        """Log Groups and the Files Inside Them
        ---
        tags: [logs]
        responses:
          200:
            description: Discovered log files grouped by source"""
        return jsonify(logs.list_logs())

    @app.get("/api/logs/<key>/tail")
    def tail_log(key):
        """Tail of One Log File
        ---
        tags: [logs]
        parameters:
          - name: key
            in: path
            required: true
            type: string
            description: Opaque server-mangled log file handle
          - name: lines
            in: query
            required: false
            type: integer
            description: How many lines to return from the end of the file
        responses:
          200:
            description: Last N lines, ANSI stripped
          400:
            description: lines was not an integer"""
        # Cap the request-controlled line count server-side; max_bytes is the
        # ceiling on how much of a possibly-huge file one call can pull.
        lines = request.args.get("lines", 80)
        try:
            n = int(lines)
        except (TypeError, ValueError):
            return jsonify(error="lines must be an integer"), 400
        return jsonify(logs.tail(key, n))

    @app.get("/api/logs/<key>/summary")
    def summary_log(key):
        """Level and Volume Breakdown of One Log
        ---
        tags: [logs]
        parameters:
          - name: key
            in: path
            required: true
            type: string
            description: Opaque server-mangled log file handle
          - name: lines
            in: query
            required: false
            type: integer
            description: Size of the backward read window to aggregate
        responses:
          200:
            description: Level counts, per-minute histogram and busiest sources
          400:
            description: lines was not an integer
        description: >
          Counts over the same bounded backward window the tail uses, so the
          header chips and the numbers agree. Cheap enough to sit above the
          viewer permanently.
        """
        lines = request.args.get("lines", 2000)
        try:
            n = int(lines)
        except (TypeError, ValueError):
            return jsonify(error="lines must be an integer"), 400
        return jsonify(logs.summary(key, n))

    @app.get("/api/trace/<key>")
    def trace_metrics(key):
        """Call Graph Metrics From the Native Analyzer Trace
        ---
        tags: [logs]
        parameters:
          - name: key
            in: path
            required: true
            type: string
            description: Opaque handle of a trace file
        responses:
          200:
            description: Event counts, nesting depth, timing and memory totals
        description: >
          trace.txt is a spdlog call-graph dump, not a log, and none of the
          generic-log assumptions hold for it: no levels, no logger names, no
          timestamps. It also embeds raw binary from the extractor, so the
          reader decodes with replacement rather than failing the whole request
          on one bad byte.

          Reads backward from EOF over a bounded window and never loads the
          whole file, so this stays cheap as trace.txt grows without rotation.
        """
        return jsonify(trace.analyze(key))

    @app.get("/api/vm-metrics")
    def vm_metrics():
        """Live Guest Metrics Collected Over SSH and SFTP
        ---
        tags: [vms]
        responses:
          200:
            description: Last collection, whether or not it succeeded
        description: >
          CPU, memory, disk, network and top processes from inside each guest
          the panel holds credentials for, read from qiling_dlls/vm_info.json.

          Returns immediately from a background collector rather than opening an
          SSH session inline, so this endpoint never blocks behind a handshake
          timeout on a powered-off guest. `state` is the field to branch on:
          pending means the first collection has not landed yet, and `down`
          carries the reason in `error`.
        """
        return jsonify(vmmetrics.snapshot())

    @app.get("/api/config")
    def panel_config():
        """Non-Secret Runtime Config, so the UI Never Hardcodes a Port
        ---
        tags: [panel]
        responses:
          200:
            description: Ports, repo paths and the compose project list"""
        return jsonify({
            "repo": str(config.REPO),
            "panel": {"host": config.bind_host(), "port": config.panel_port()},
            "analyzer": config.analyzer_base(),
            "ml": config.ml_base(),
            "malapi": config.malapi_base(),
            "ml_auth": bool(config.ml_token()),
            "compose_projects": [
                {"label": p["label"], "services": p["services"]}
                for p in config.compose_projects()
            ],
        })

    @app.get("/api/analysis/config")
    def analysis_config():
        """Every Pipeline and Analysis Option the Analyzer Will Use
        ---
        tags: [analysis]
        responses:
          200:
            description: Named pipelines with resolved phase order, the live phase
              catalog, and the artifact/MEGA upload options
        description: >
          Reads `pipelines/*.yaml` and `config/artifacts.yaml` from disk and
          resolves each pipeline against the phase catalog the analyzer
          publishes on its own `GET /phases`, so the page shows the order the
          binary will actually run rather than the order the file lists.

          A pipeline the analyzer would reject - a phase name that is not in the
          catalog, a malformed document, an unknown artifact option - is reported
          as broken with the reason attached instead of being filtered out of the
          listing. When the analyzer is down the catalog is absent and the phase
          check is skipped, which is stated in the payload rather than papered
          over with a stale copy of the names.

          Values in a pipeline's `environment:` block that look like credentials
          are masked before they leave the process.

          Read-only: authoring a pipeline means editing its YAML, which the
          analyzer already reads. Nothing here writes or starts a run.
        """
        try:
            return jsonify(analysis.snapshot())
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({"error": f"{type(exc).__name__}: {exc}"})

    # --- analysis configuration: writes ---------------------------------------
    #
    # These are the only routes in the panel that change a file the analyzer
    # reads. Everything else here reports. Each one is narrow on purpose: a
    # fixed set of keys, values validated with the analyzer's own rules, and the
    # edited text re-parsed and checked before it replaces anything. What a
    # route cannot express - which file, which key, what a valid value is - is
    # never taken from the request.
    #
    # The edited text is validated, not just accepted, because these files are
    # not forgiving: an unknown key in config/artifacts.yaml or an unknown phase
    # name in a pipeline is a startup failure, not a warning. A toggle that could
    # leave the analyzer unable to start would be worse than no toggle.

    def _bad(exc: Exception, status: int = 400):
        detail = str(exc)
        return jsonify(ok=False, error=detail), status

    @app.get("/api/analysis/settings")
    def get_analysis_settings():
        """Global Analysis Settings
        ---
        tags: [analysis]
        responses:
          200:
            description: Every setting, with whether it is set and to what
          400:
            description: The file exists but is not a YAML map
        description: >
          config/analysis.yaml, the settings that apply to every run regardless of
          which pipeline was selected. Reads alongside the per-pipeline
          `environment:` block; where the two disagree about the same key, this
          file wins, because it is applied after it. A key absent here is
          reported with `present: false` and falls back to the pipeline's value
          and then to the binary's default.

          `unknown` lists any key in the file that is not a setting the analyzer
          reads. The analyzer refuses to start on one, so it is surfaced here
          rather than only as an exit code 2.
        """
        try:
            return jsonify(analysis_settings.snapshot(config.REPO))
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400

    @app.put("/api/analysis/settings")
    def put_analysis_settings():
        """Set or Clear Global Analysis Settings
        ---
        tags: [analysis]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              additionalProperties:
                description: >
                  Setting name to value. A null value removes the key, returning
                  the setting to the binary default and to whatever the selected
                  pipeline says.
              example: {"ML_SKIP": false, "ML_THRESHOLD": 0.6}
        responses:
          200:
            description: The settings as they now stand on disk
          400:
            description: An unknown key, a bad value, or an edit that would not parse
        description: >
          Rewrites only the keys present in the body, in place, leaving the rest
          of the file - including every comment - byte-identical. PyYAML's round
          trip would strip this file's explanation of the precedence rules, which
          is the one thing a reader needs.

          Values are validated against the same rules the analyzer applies, and
          the result is re-parsed before it lands, so a request cannot leave
          behind a config the analyzer would refuse at startup. Takes effect on
          the analyzer's next run; the file is read once at startup.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        try:
            result = analysis_settings.write_settings(config.REPO, body)
        except ValueError as exc:
            return _bad(exc)
        except OSError as exc:
            return _bad(exc, 500)
        return jsonify(ok=True, settings=result)

    @app.post("/api/analysis/artifact-options")
    def set_artifact_options():
        """Change the Bundle and MEGA Upload Options
        ---
        tags: [analysis]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                store_artifact: {type: boolean}
                upload_artifacts: {type: boolean}
                remote_root: {type: string}
                timeout_seconds: {type: integer}
        responses:
          200:
            description: The options as they now stand on disk
          400:
            description: An unknown key, a bad value, or an edit that would not parse
        description: >
          Rewrites only the keys present in the body, in place, leaving the rest
          of the file - including every comment - byte-identical. PyYAML's round
          trip would strip the file's documentation, and those comments are the
          only explanation of what each option is for.

          Values are validated with the rules `load_artifact_options()` enforces,
          and the result is re-parsed before it lands, so a request cannot leave
          behind a config the analyzer would refuse at startup. Takes effect on
          the analyzer's next run; the file is read once at startup.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        try:
            options = analysis.write_artifact_options(body)
        except ValueError as exc:
            return _bad(exc)
        except OSError as exc:
            return _bad(exc, 500)
        return jsonify(ok=True, artifacts=options)

    @app.post("/api/analysis/pipeline/environment")
    def set_pipeline_environment():
        """Set or Clear Pipeline Environment Options
        ---
        tags: [analysis]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [pipeline]
              properties:
                pipeline: {type: string}
                environment:
                  type: object
                  description: >
                    Option name to value. Only the options the analyzer reads are
                    accepted, and a flag set false removes the key rather than
                    writing an "off" value.
        responses:
          200:
            description: The pipeline entry as it now stands on disk
          400:
            description: Unknown option, bad value, or an edit that would not parse
          404:
            description: No such pipeline
        description: >
          Writes into the `environment:` block of one pipeline in pipelines/,
          leaving the phase lists and the file's comments alone.

          Only variables the analyzer actually reads are writable, each carrying
          the source line that reads it. An option the binary ignores is a
          switch that lies, so there are none here. A name that looks like a
          credential is refused outright: the vault and .env are where those
          belong, and a browser form is not.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        updates = body.get("environment")
        if not isinstance(updates, dict):
            return jsonify(ok=False, error="'environment' must be an object"), 400
        try:
            entry = analysis.write_environment(str(body.get("pipeline") or ""), updates)
        except ValueError as exc:
            return _bad(exc)
        except OSError as exc:
            return _bad(exc, 500)
        return jsonify(ok=True, pipeline=entry)

    @app.post("/api/analysis/pipeline/rush")
    def set_pipeline_rush():
        """Apply or Undo the Phase-Rush Triage Profile
        ---
        tags: [analysis]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [pipeline, enabled]
              properties:
                pipeline: {type: string}
                enabled: {type: boolean}
        responses:
          200:
            description: The pipeline entry as it now stands on disk
          400:
            description: Nothing to apply or restore, or the edit did not verify
          404:
            description: No such pipeline
        description: >
          Drops the phases that dominate wall clock - radare2 and its call
          graphs, capa, cminer, hexdump, the internet CTI lookups and the ML
          score - from every `phases: [...]` list in one pipeline, or puts them
          back.

          Applying records each original list as a `# phase-rush: [...]` comment
          directly above the list it trimmed, which is what makes undoing it
          exact rather than a guess, and what explains an empty stage to whoever
          reads the YAML next. Only inline phase lists are edited; a block-style
          pipeline is refused with an explanation instead of being rewritten
          blind.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            return jsonify(ok=False, error="'enabled' must be true or false"), 400
        try:
            entry = analysis.set_rush(str(body.get("pipeline") or ""), enabled)
        except ValueError as exc:
            return _bad(exc)
        except OSError as exc:
            return _bad(exc, 500)
        return jsonify(ok=True, pipeline=entry)

    @app.post("/api/analysis/pipeline/yara-gen")
    def set_pipeline_yara_gen():
        """Enable or Disable YARA Rule Generation
        ---
        tags: [analysis]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [pipeline, enabled]
              properties:
                pipeline: {type: string}
                enabled: {type: boolean}
        responses:
          200:
            description: The updated pipeline entry
          400:
            description: Refused, with the reason
        description: >
          Adds or removes the `yara_gen` phase in a pipeline's phase lists.

          It edits the same inline `phases: [...]` lists as the phase-rush
          toggle, so the wizard preview, the planner and this control cannot
          disagree about what the file says. The phase is inserted immediately
          BEFORE `export`, because a rule file written after the artifact set is
          assembled is a rule file nobody receives.

          The write is verified before it is committed: if the phase would be
          missing, or would land after `export`, nothing is written at all.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            return jsonify(ok=False, error="'enabled' must be true or false"), 400
        try:
            entry = analysis.set_yara_gen(str(body.get("pipeline") or ""), enabled)
        except ValueError as exc:
            return _bad(exc)
        except OSError as exc:
            return _bad(exc, 500)
        return jsonify(ok=True, pipeline=entry)

    @app.post("/api/analysis/pipeline")
    def create_pipeline():
        """Save a New Pipeline From the Builder
        ---
        tags: [analysis]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [name, content]
              properties:
                name: {type: string}
                content: {type: string}
        responses:
          201:
            description: The new pipeline entry
          400:
            description: Bad name, unparseable content, or no phases
          409:
            description: A pipeline with that name already exists
        description: >
          Writes pipelines/<name>.yaml and refuses to overwrite: an existing
          pipeline is someone's work, and a save that silently replaces it is how
          a tuned config disappears. Editing an existing file goes through the
          environment route, which touches only the keys it was asked to touch.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        try:
            entry = analysis.save_pipeline(str(body.get("name") or ""),
                                          str(body.get("content") or ""))
        except ValueError as exc:
            return _bad(exc)
        except FileExistsError as exc:
            return _bad(exc, 409)
        except OSError as exc:
            return _bad(exc, 500)
        return jsonify(ok=True, pipeline=entry), 201

    # --- documentation ------------------------------------------------------

    @app.get("/api/docs")
    def endpoint_docs():
        """Every Endpoint This Lab Exposes, as One Browsable Reference
        ---
        tags: [documentation]
        responses:
          200:
            description: Route catalogue for the panel and every service"""
        try:
            return jsonify(docs.catalog())
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({"error": f"{type(exc).__name__}: {exc}"})

    # --- containers ----------------------------------------------------------

    @app.get("/api/containers")
    def list_containers():
        """Live Docker State in the ContainerList Shape the UI Expects
        ---
        tags: [containers]
        responses:
          200:
            description: Per-container metrics plus engine-wide aggregates
        description: >
          Same data as stats._containers() but unsummarised: per-container
          metrics plus the engine-wide aggregates (Docker Desktop overall).
          Never 500s - a stopped daemon degrades to available:false with the
          reason attached, matching the probe philosophy in services.py.
        """
        try:
            return jsonify(containers.list_containers())
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({
                "daemon": {"available": False, "running": False,
                           "version": None, "error": f"{type(exc).__name__}: {exc}"},
                "engine": None, "storage": None, "projects": [],
                "compose_files": [],
                "stats_available": False, "stats_containers": 0,
                "updated_at": None,
            })

    @app.post("/api/containers/<project>/<service>/<action>")
    def control_container(project, service, action):
        """Start or Stop One Compose Service
        ---
        tags: [containers]
        parameters:
          - name: project
            in: path
            required: true
            type: string
            description: Compose project label, e.g. ia
          - name: service
            in: path
            required: true
            type: string
            description: Compose service name
          - name: action
            in: path
            required: true
            type: string
            description: start or stop
        responses:
          200:
            description: Command accepted
          400:
            description: Unknown action
          404:
            description: Service is not in the allowlist
          502:
            description: docker refused
        description: >
          project/service are validated against compose_projects() inside
          containers.control(); anything not listed there is rejected before
          any docker command runs, so a crafted URL cannot touch arbitrary
          containers. The snapshot cache is invalidated on success, so the
          next GET polls fresh rather than serving the stale view.
        """
        if action not in ("start", "stop"):
            return jsonify(error="action must be start or stop"), 400
        if not config.service_allowed(project, service):
            return jsonify(error="unknown service " + project + "/" + service), 404
        ok, detail = containers.control(project, service, action)
        code = 200 if ok else 502
        return jsonify(ok=ok, detail=detail), code

    @app.post("/api/containers/<project>/build")
    def build_compose_project(project):
        """Start an Image Build for an Allowlisted Compose Project
        ---
        tags: [containers]
        parameters:
          - name: project
            in: path
            required: true
            type: string
            description: Compose project label from the panel configuration
        responses:
          202:
            description: Build started or already running
          404:
            description: Compose project is not in the allowlist
        description: >
          Returns a job handle immediately rather than blocking: a build runs
          for minutes and its log is the useful part. Poll
          GET /api/containers/build/<job_id> for output, then the compose
          snapshot cache is invalidated so the next read shows new images.

          A second call while a build is already running for the same project
          returns that job rather than starting a competing one, because two
          concurrent compose builds contend on the same Docker build cache.
        """
        if not any(item["label"] == project for item in config.compose_projects()):
            return jsonify(ok=False, error="unknown compose project " + project), 404
        ok, info = containers.start_build(project)
        if not ok:
            return jsonify(ok=False, error=info.get("error", "could not start build")), 404
        return jsonify(ok=True, **info), 202

    @app.get("/api/containers/build/<job_id>")
    def build_compose_job(job_id):
        """Live Output of a Build Started Above
        ---
        tags: [containers]
        parameters:
          - name: job_id
            in: path
            required: true
            type: string
            description: Job handle from POST /api/containers/<project>/build
        responses:
          200:
            description: Job state, log lines so far and elapsed seconds
          404:
            description: Unknown job id
        description: >
          `state` is running, done or error. `lines` is the whole log so far and
          grows with each poll; the server keeps the last 4000 lines and reports
          how many it dropped in `dropped`, because the tail of a build log is
          the part that explains a failure. Jobs are in-memory and last an hour.
        """
        job = containers.build_job(job_id)
        if job is None:
            return jsonify(error="unknown job id"), 404
        return jsonify(job)

    @app.get("/api/containers/<project>/compose")
    def get_compose_file(project):
        """Get the Content of a Compose File with Parsed Services
        ---
        tags: [containers]
        parameters:
          - name: project
            in: path
            required: true
            type: string
            description: Compose project label from the panel configuration
        responses:
          200:
            description: Compose file content and parsed services
          404:
            description: Compose project is not in the allowlist
        description: >
          Returns the raw YAML content, every service with its full parsed
          configuration, and the character spans PyYAML's own node marks say to
          colour. The parse is the server's; the client only paints it.

          This reads a file that may hold literal secrets in `environment`, so
          it is gated exactly like the rest of /api and stays loopback-only.
        """
        target = next((p for p in config.compose_projects() if p["label"] == project), None)
        if target is None:
            return jsonify(error="unknown compose project " + project), 404
        try:
            content = target["file"].read_text(encoding="utf-8")
        except OSError as exc:
            return jsonify(error=f"could not read compose file: {exc}"), 500
        try:
            relative = str(target["file"].relative_to(config.REPO))
        except ValueError:
            relative = str(target["file"])
        return jsonify({
            "label": project,
            "file": relative,
            "content": content,
            "services": _compose_services(content),
            "spans": _yaml_spans(content),
        })

    # --- evidence artifacts (local bundles + MEGA) ----------------------------

    @app.get("/api/artifacts")
    def artifacts_bundles():
        """Local Evidence Tarballs and Their MEGA Copies
        ---
        tags: [artifacts]
        parameters:
          - name: remote_root
            in: query
            required: false
            type: string
            description: MEGA folder to list instead of the account root
          - name: refresh
            in: query
            required: false
            type: string
            description: pass 1 to bypass both caches (the Rescan button)
        responses:
          200:
            description: Both ends, even when MEGA is unreachable
        description: >
          `local` walks exports/ for `<artifact>_artifact/` bundles and reports
          the sealed tarball, its recorded digest and whether re-hashing it
          agrees. `remote` is the same bundles read back off MEGA through
          mega/list.py, and `transfer` is the effective throughput between
          consecutive uploads.

          Listing remains read-only. Uploading stays a CLI action
          (`python mega/upload.py --artifact <name>`); an explicit recovery
          action is available separately for downloading and verifying an
          existing remote bundle.

          The remote half is a third-party call and degrades to
          `available: false` with a reason rather than failing the request -
          MEGAcmd missing, no session and timeout are all ordinary states. It
          runs under a wall-clock budget so a slow MEGA cannot hold the request
          open; a truncated answer says so instead of looking complete.

          The rate is an upper bound, not a measured line rate: MEGAcmd records
          when an upload finished and nothing records when it started, so the
          interval between two bundles includes however long the operator
          waited before pressing upload.

          Cached for 5 minutes, because nothing writes to MEGA on a timer.
          `?refresh=1` bypasses both caches so the Rescan button reflects an
          upload that just happened rather than one from five minutes ago.
        """
        try:
            return jsonify(artifacts.snapshot(
                request.args.get("remote_root", "/"),
                request.args.get("refresh") == "1",
            ))
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({"generated_at": None, "local": None, "remote": None,
                            "transfer": None,
                            "error": f"{type(exc).__name__}: {exc}"})

    @app.get("/api/artifacts/local/<name>/archive")
    def artifact_local_archive(name: str):
        """Download a Local Evidence Archive
        ---
        tags: [artifacts]
        parameters:
          - name: name
            in: path
            required: true
            type: string
            description: Plain artifact name, without the _artifact suffix
        responses:
          200:
            description: The local evidence archive as an attachment
          404:
            description: The artifact or archive is not present locally
        description: >
          Resolves only an evidence archive beneath the repository exports
          directory. The artifact name is treated as a single path component;
          client-provided filesystem paths are never accepted.
        """
        if not artifacts.valid_name(name):
            return jsonify(error="invalid artifact name"), 400
        archive = artifacts.local_archive(name)
        if archive is None:
            return jsonify(error="local artifact archive not found"), 404
        return send_file(
            archive,
            as_attachment=True,
            download_name=archive.name,
            mimetype="application/gzip",
        )

    @app.post("/api/artifacts/recover")
    def artifact_recover():
        """Recover a Remote Evidence Archive from MEGA
        ---
        tags: [artifacts]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [name]
              properties:
                name: {type: string}
                remote_root: {type: string}
        responses:
          200:
            description: Bundle downloaded and verified
          400:
            description: Invalid artifact name or MEGA root
          404:
            description: Bundle is not present in the selected MEGA root
          409:
            description: A local bundle already exists
          502:
            description: MEGA recovery failed verification or download
          503:
            description: MEGA is unavailable or not authenticated
          504:
            description: Recovery timed out
        description: >
          Runs mega/recover.py with an argument list (never through a shell).
          The script downloads the bundle into exports/ and verifies its
          archive digest before reporting success. Only a bundle confirmed by
          the panel's MEGA listing can be recovered.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="request body must be a JSON object"), 400
        raw_name = body.get("name")
        if not isinstance(raw_name, str):
            return jsonify(error="artifact name must be a string"), 400
        name = raw_name.strip()
        raw_remote_root = body.get("remote_root", "/")
        if not isinstance(raw_remote_root, str):
            return jsonify(error="MEGA remote root must be a string"), 400
        remote_root = raw_remote_root.strip() or "/"
        if not artifacts.valid_name(name):
            return jsonify(error="invalid artifact name"), 400
        if (not remote_root.startswith("/") or "\\" in remote_root
                or "\x00" in remote_root
                or any(part == ".." for part in remote_root.split("/"))):
            return jsonify(error="invalid MEGA remote root"), 400

        remote = artifacts.remote(remote_root)
        if not remote.get("available"):
            return jsonify(error=remote.get("reason") or "MEGA is unavailable"), 503
        if not any(bundle.get("name") == name for bundle in remote.get("bundles", [])):
            return jsonify(error="artifact is not present in the selected MEGA root"), 404

        exports = config.REPO / "exports"
        local_dir = exports / f"{name}{artifacts.BUNDLE_SUFFIX}"
        if local_dir.exists():
            return jsonify(error="a local bundle already exists; refusing to overwrite it"), 409

        command = [
            sys.executable,
            str(config.REPO / "mega" / "recover.py"),
            "--artifact", name,
            "--remote-root", remote_root,
            "--out-root", str(exports),
            "--timeout", "240",
        ]
        try:
            result = subprocess.run(
                command,
                cwd=config.REPO,
                capture_output=True,
                text=True,
                timeout=270,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return jsonify(error="MEGA recovery exceeded the 270-second time limit"), 504
        except OSError as exc:
            return jsonify(error=f"could not start MEGA recovery: {exc}"), 502

        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            return jsonify(error=detail or f"MEGA recovery failed (exit {result.returncode})"), 502

        artifacts.invalidate_local_cache()
        return jsonify(
            ok=True,
            detail=(result.stdout or "Artifact recovered and verified.").strip()[-4000:],
        )

    @app.post("/api/artifacts/export")
    def artifact_export():
        """Seal and Upload a Local Evidence Bundle to MEGA
        ---
        tags: [artifacts]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [name]
              properties:
                name: {type: string}
                remote_root: {type: string}
        responses:
          202:
            description: Export started, or a job already running for this bundle
          400:
            description: Invalid artifact name or MEGA root
          403:
            description: upload_artifacts is false in config/artifacts.yaml
          404:
            description: No local bundle with that name
        description: >
          The mirror of recovery: pushes a bundle that is on disk up to MEGA
          through mega/upload.py, which is the same script and the same
          determinism guarantees an operator gets from the CLI.

          Returns a job handle immediately - sealing a large bundle and pushing
          it over a consumer link takes minutes, and the log is the useful part.
          Poll GET /api/artifacts/export/<job_id>.

          Gated on `upload_artifacts` in config/artifacts.yaml. That option is
          the operator saying this lab does not send evidence off the host, and a
          button in a browser has to honour it exactly as the analyzer does.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        raw_name = body.get("name")
        if not isinstance(raw_name, str):
            return jsonify(ok=False, error="artifact name must be a string"), 400
        ok, info = artifacts.start_export(raw_name.strip(),
                                          str(body.get("remote_root") or "/"))
        if not ok:
            status = 403 if info.get("error") == "uploading is disabled" else 400
            if info.get("error", "").startswith("no local bundle"):
                status = 404
            return jsonify(ok=False, **info), status
        return jsonify(ok=True, **info), 202

    @app.get("/api/artifacts/export/<job_id>")
    def artifact_export_job(job_id: str):
        """Live Output of an Export Started Above
        ---
        tags: [artifacts]
        parameters:
          - name: job_id
            in: path
            required: true
            type: string
            description: Job handle from POST /api/artifacts/export
        responses:
          200:
            description: Job state, uploader output so far and elapsed seconds
          404:
            description: Unknown job id
        description: >
          `state` is running, done or error, and `lines` is the whole uploader
          output so far. The server keeps the last 4000 lines and reports how
          many it dropped, because the tail is the part that explains a failure.
          Jobs are in-memory and last an hour.
        """
        job = artifacts.export_job(job_id)
        if job is None:
            return jsonify(error="unknown job id"), 404
        return jsonify(job)

    # --- virtual machines ----------------------------------------------------

    @app.get("/api/vms")
    def list_vms():
        """Registered VirtualBox Machines With IP, Live Services and Metrics
        ---
        tags: [vms]
        responses:
          200:
            description: Every machine, even when VirtualBox is absent
        description: >
          One showvminfo per registered machine, plus a concurrent TCP probe
          against the services that are open on it. Only running machines are
          probed - a powered-off guest cannot be listening, and probing it would
          spend ten timeouts to report what the power state already says.
          Each machine also includes a bounded tail of its latest VBox.log.
          The machine with no IP shows one, because that is the gap worth
          seeing, not a gap to paper over.

          Duplicate registrations are collapsed by UUID and the drop is
          reported in counts.duplicates rather than done silently. Metrics come
          from the cached SSH/SFTP collection and are null for any machine the
          panel holds no credentials for - which is a different fact from a
          machine reporting zero.
        """
        try:
            return jsonify(vms.listing())
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({"generated_at": None, "vms": [],
                            "available": False, "duplicate_names": [],
                            "counts": {"total": 0, "running": 0, "duplicates": 0},
                            "error": f"{type(exc).__name__}: {exc}"})

    @app.post("/api/vms/<action>")
    def control_vm(action):
        """Start or Stop a Registered VirtualBox Machine
        ---
        tags: [vms]
        parameters:
          - name: action
            in: path
            required: true
            type: string
            description: start or stop
          - name: name
            in: body
            required: true
            type: string
            schema:
              type: object
              properties:
                name: {type: string}
                headless: {type: boolean, default: true}
        responses:
          200:
            description: Command accepted
          400:
            description: Unknown action, or no name given
          404:
            description: Not a registered machine
          502:
            description: VBoxManage refused
        description: >
          The name arrives in the body rather than the path because a VirtualBox
          machine name is free text - it can contain slashes and spaces, and a
          crafted name in a URL is a name that never got quoted. It is checked
          against the registered machine list inside vms.control() before
          anything runs, so an unknown name is rejected rather than passed on.
          `stop` is a hard poweroff, not an ACPI shutdown: malware in the guest
          can ignore a power button, and a sandbox that will not power down is
          worse than one that loses a snapshot. The listing cache is dropped on
          success so the next poll shows the new state immediately.

          `headless` chooses `VBoxManage startvm --type headless|gui` and is
          only read for `start`. It defaults to true when absent, which is the
          mode this lab was built around - so an older client that never sends
          the field keeps booting headless rather than popping a window onto
          somebody's console. The resolved mode is echoed back so the operator's
          confirmation can name what was actually done.
        """
        if action not in ("start", "stop"):
            return jsonify(ok=False, error="action must be start or stop"), 400
        body = request.get_json(silent=True) or {}
        # Anything other than an explicit JSON false means headless. Guessing
        # "gui" from a typo would open a window nobody asked for.
        headless = body.get("headless", True) is not False
        result = vms.control(str(body.get("name") or ""), action, headless=headless)
        code = 200 if result["ok"] else 502
        return jsonify(result), code

    # --- build: the analyzer, its dependencies, and one build at a time ---------

    @app.get("/api/build")
    def build_overview():
        """Dependencies and Built Executables
        ---
        tags: [build]
        responses:
          200:
            description: Dependency report plus whatever is currently built
        description: >
          One call, because the two halves answer the same question - "can this
          be built right now?" - and a panel that fetched them separately could
          render a green toolchain next to a stale binary.

          The dependency list is derived from what CMakeLists.txt actually
          declares rather than from a list kept here, so adding a find_package()
          to the project shows up without touching the panel. The WIN32 branch
          wins where both branches declare the same dependency, because that is
          the one this host compiles against; anything outside an if/else is
          kept either way.
        """
        return jsonify(build.overview())

    @app.post("/api/build/check-deps")
    def build_check_deps():
        """Re-Check Dependencies
        ---
        tags: [build]
        responses:
          200:
            description: A fresh toolchain and analysis-stack report
        description: >
          On demand rather than only on load, because the stack half of the
          report includes services that can be started after the page is open -
          MalAPI and the ML scorer answer on their own ports, and a report
          computed at page load would keep reporting them down until a reload.

          The check is read-only. It walks the repository and makes two short
          HTTP probes to loopback; it never installs anything.
        """
        return jsonify({
            "toolchain": build.dependencies(),
            "stack": build.stack_dependencies(),
        })

    @app.get("/api/build/inspect")
    def build_inspect():
        """Provenance, Freshness and Validation
        ---
        tags: [build]
        responses:
          200:
            description: Identity of the built binary, whether it is current, and
                         whether it works
        description: >
          Everything needed to answer "can I trust the executable in build-ucrt/":
          the commit it was built from (compared against the working tree), whether
          it predates the sources it is built from, and a set of read-only checks
          that actually run it.

          The checks never build and never write to the repository. The DLL check
          exists because this project has already failed that way: Graphviz ships
          its own zlib1.dll, it sat earlier on PATH, and the analyzer died at load
          time with STATUS_ENTRYPOINT_NOT_FOUND and no output at all.
        """
        return jsonify({
            "provenance": build_checks.provenance(),
            "freshness": build_checks.freshness(),
            "validation": build_checks.validation(),
            "configuration": build_checks.build_configuration(),
        })

    @app.get("/api/build/tests")
    def build_tests():
        """List the Tests
        ---
        tags: [build]
        responses:
          200:
            description: Every test the admin can choose from, with side effects
        description: >
          A catalogue rather than one suite, because the entries are not
          equivalent: two write files under the AppData root and one runs the
          analyzer end to end. Each entry declares what it touches so a
          destructive test is never a surprise behind a generic button.

          pytest suites are listed whether or not pytest is installed, marked
          unavailable rather than hidden, so their absence is visible instead of
          looking like they do not exist.
        """
        return jsonify(build_checks.catalogue())

    @app.post("/api/build/tests")
    def build_tests_start():
        """Run the Chosen Tests
        ---
        tags: [build]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [ids]
              properties:
                ids: {type: array, items: {type: string}}
        responses:
          200:
            description: Job handle, or a refusal with the reason
        description: >
          Runs the selected tests in order as one job and streams the log.

          Analyzer-backed entries execute with IA_ARTIFACT_UPLOAD=0. That is not
          optional: config/artifacts.yaml ships upload_artifacts: true, so
          without it a test started from a browser button would push an evidence
          bundle to the operator's cloud account.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "body must be a JSON object"}), 400
        ids = body.get("ids")
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            return jsonify({"ok": False,
                            "error": "'ids' must be a list of strings"}), 400
        result = build_checks.start_tests([i.strip() for i in ids if i.strip()])
        return (jsonify(result) if result.get("ok")
                else (jsonify(result), 409 if "already" in str(result.get("error"))
                       else 400))

    @app.get("/api/utils")
    def utils_overview():
        """Utils - state of the vendored analysis stack
        ---
        tags: [utils]
        responses:
          200:
            description: SBOM, MalAPI rules, YARA packs and yarGen-Go, plus the
                         runnable catalogue
        description: >
          Four things that can only be maintained by reading the source: the
          CycloneDX SBOM, the MalAPI rule checkout (malt/), the unpacked YARA
          rule packs, and yarGen-Go's databases.

          One call for all four, because they are one page and four requests
          could render four cards describing four different moments.

          Two report an action that does not exist rather than omitting it.
          yara-rules/ is a plain directory with no recorded upstream, so there
          is no update to offer; saying so is more useful than a page that
          quietly has one fewer button than the admin expects.
        """
        return jsonify(utils.overview())

    @app.post("/api/utils")
    def utils_start():
        """Run a Chosen Utility
        ---
        tags: [utils]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [ids]
              properties:
                ids: {type: array, items: {type: string}}
                options:
                  type: object
                  description: >
                    Per-utility switches from the panel. Currently only
                    `ignore_compile_failures`, for the YARA check: when true,
                    rule files that do not compile are named in the log and
                    counted but do not fail the job. Persisted, so it survives
                    a page reload.
        responses:
          200:
            description: Job handle, or a refusal with the reason
        description: >
          Runs the selected utilities in order as one job and streams the log.

          The MalAPI update is `git pull --ff-only` with GIT_TERMINAL_PROMPT=0
          and it refuses outright if malt/ has local changes. That combination
          is deliberate: a browser button cannot be allowed to create a merge
          commit, block on a credential prompt with no terminal to answer it, or
          discard someone's uncommitted work.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "body must be a JSON object"}), 400
        ids = body.get("ids")
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            return jsonify({"ok": False,
                            "error": "'ids' must be a list of strings"}), 400
        options = body.get("options", {})
        if not isinstance(options, dict):
            return jsonify({"ok": False,
                            "error": "'options' must be an object"}), 400
        result = utils.start([i.strip() for i in ids if i.strip()], options)
        return (jsonify(result) if result.get("ok")
                else (jsonify(result), 409 if "already" in str(result.get("error"))
                       else 400))

    @app.put("/api/utils/yara-check")
    def utils_yara_options():
        """Set the YARA Check's Switches
        ---
        tags: [utils]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                ignore_compile_failures:
                  type: boolean
                  description: >
                    When true, rule files that do not compile are named in the
                    log and counted, but the check does not fail. Persisted in
                    config/yara_check.json.
        responses:
          200: description: New state
          400: description: Unknown option, or a non-boolean value
        description: >
          The card's checkbox calls this instead of starting a run: the compile
          check takes ~60s, and a toggle that forces a minute of compilation
          each time it is flipped is a toggle nobody flips.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "body must be a JSON object"}), 400
        try:
            state = utils.set_yara_options(body)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except RuntimeError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 503
        # yara() alongside, so the caller can update the card from one
        # response instead of polling into a state change.
        yara_now = utils.yara()
        return jsonify({"ok": True, **state,
                        "yara": {"ignore_compile_failures":
                                 yara_now.get("ignore_compile_failures")}})

    @app.post("/api/build")
    def build_start():
        """Build the Analyzer
        ---
        tags: [build]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: false
            schema:
              type: object
              properties:
                clean: {type: boolean, default: false}
        responses:
          202:
            description: Build started; poll GET /api/build/<job_id>
          409:
            description: A build is already running
          503:
            description: The toolchain or build script is not usable
        description: >
          Runs build.ps1 - the same script, with the same presets, that the
          operator runs by hand - so the panel produces the binary the terminal
          produces rather than a near-enough variant of it.

          Job-based because a full compile runs for minutes and the log is the
          part worth watching. Exactly one may run at a time: a second is refused
          rather than queued, because two concurrent builds would contend for
          build-ucrt/ and a queued build would sit invisible behind a spinner.

          `clean` deletes build-ucrt/ and reconfigures, which is slow and
          irreversible, so it is opt-in per click rather than a mode.
        """
        body = request.get_json(silent=True) or {}
        clean = bool(body.get("clean"))
        result = build.start_build(clean=clean)
        if result.get("ok"):
            return jsonify(result), 202
        if "already running" in str(result.get("error", "")):
            return jsonify(result), 409
        return jsonify(result), 503

    @app.get("/api/build/<job_id>")
    def build_job(job_id: str):
        """Live Output of a Build
        ---
        tags: [build]
        parameters:
          - name: job_id
            in: path
            required: true
            type: string
        responses:
          200:
            description: State plus the log so far
          404:
            description: Unknown or expired job
        description: >
          The log is returned whole rather than tailed, so a reload restores the
          full output instead of the last screen of it. build.py keeps the head
          as well as the tail precisely so the cmake configure lines - where a
          missing dependency announces itself - survive a long compile.
        """
        job = build.job(job_id)
        if job is None:
            return jsonify(error="unknown or expired job id"), 404
        return jsonify(job)

    @app.get("/api/build/current")
    def build_current():
        """The Running Build, if Any
        ---
        tags: [build]
        responses:
          200:
            description: The running job, or null
        description: >
          So a reload reattaches to a build that is already going instead of
          showing an idle panel while the compiler works.
        """
        return jsonify(build.current())

    # --- clamav (guest on the Qiling VM) -------------------------------------

    @app.get("/api/clamd/status")
    def clamd_status():
        """Connection-Test Checks Against the Local clamd
        ---
        tags: [clamav]
        responses:
          200:
            description: Check results, even when nothing answered
        description: >
          Read-only, local only: nothing here SSHes into the VM or starts a
          scan. The daemon lives inside the analysis VM and answers over SSH,
          so a local PING/VERSION reflects a local clamd if one exists - the
          payload says so rather than dressing a local check up as the
          guest's health.
        """
        try:
            return jsonify(clamd.status())
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({"reachable": False, "ok": False, "checks": [],
                            "error": f"{type(exc).__name__}: {exc}"})

    @app.get("/api/clamd/results")
    def clamd_results():
        """Scan Result JSONs Written by the Scanner
        ---
        tags: [clamav]
        responses:
          200:
            description: Result files, newest first
        description: >
          Verdicts are read from the files the scanner wrote, never recomputed.
          A zero-byte file (interrupted SFTP download) surfaces as failed with
          its reason instead of being silently dropped.
        """
        try:
            return jsonify(clamd.results())
        except Exception as exc:  # noqa: BLE001
            return jsonify({"present": False, "file_count": 0, "counts": {},
                            "files": [], "error": f"{type(exc).__name__}: {exc}"})

    # --- qiling (emulation harness) ------------------------------------------

    @app.get("/api/qiling/runs")
    def qiling_runs():
        """Emulation Run Bundles and Rootfs/harness State
        ---
        tags: [qiling]
        responses:
          200:
            description: Run summaries, harness state and the service log tail
        description: >
          Reads summary.json and the trace tail straight out of each
          *_qiling_out.zip without extracting the (large) memory dumps.
        """
        try:
            return jsonify(qiling.runs())
        except Exception as exc:  # noqa: BLE001
            return jsonify({"present": False, "file_count": 0, "runs": [],
                            "error": f"{type(exc).__name__}: {exc}"})

    @app.get("/api/qiling/status")
    def qiling_status():
        """Check the Qiling Analysis VM: VBoxManage, Registration, Power, TCP
        ---
        tags: [qiling]
        responses:
          200:
            description: Per-check results
        description: >
          Same checks the admin-terminal Qiling VM Control screen runs, so the
          panel cannot disagree with it. No SSH login here (that needs a
          username and would prompt); reachability is a TCP connect.
        """
        try:
            return jsonify(qiling.vm_status())
        except Exception as exc:  # noqa: BLE001
            return jsonify({"available": False, "ok": False, "checks": [],
                            "error": f"{type(exc).__name__}: {exc}"})

    @app.get("/api/qiling/vm")
    def qiling_vm_metrics():
        """Live CPU and RAM of the Running VM, Read over SSH
        ---
        tags: [qiling]
        responses:
          200:
            description: Guest metrics, or why they are unavailable
        description: >
          Degrades to available:false with the reason when the VM is powered
          off or SSH times out - a powered-off guest is not a guest idling
          at 0%.
        """
        try:
            return jsonify(qiling.guest_metrics())
        except Exception as exc:  # noqa: BLE001
            return jsonify({"available": False, "reachable": False,
                            "error": f"{type(exc).__name__}: {exc}"})

    @app.post("/api/qiling/rootfs")
    def qiling_generate_rootfs():
        """Start a Rootfs Build and Get a Job Handle to Poll
        ---
        tags: [qiling]
        responses:
          202:
            description: Job accepted
          500:
            description: Could not start
        description: >
          The build runs dll_collector.bat elevated: a Windows UAC prompt
          appears on the machine running the panel (the operator sees it, the
          browser never does). It runs on a worker thread; poll
          GET /api/qiling/rootfs/job_id.
        """
        try:
            return jsonify(qiling.generate_rootfs()), 202
        except Exception as exc:  # noqa: BLE001
            return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 500

    @app.get("/api/qiling/rootfs/<job_id>")
    def qiling_rootfs_job(job_id):
        """Poll a Rootfs Build Job
        ---
        tags: [qiling]
        parameters:
          - name: job_id
            in: path
            required: true
            type: string
            description: Job handle from POST /api/qiling/rootfs
        responses:
          200:
            description: Job state
          404:
            description: Unknown job id"""
        job = qiling.rootfs_job(job_id)
        if job is None:
            return jsonify(error="unknown job id"), 404
        return jsonify(job)

    # --- network map --------------------------------------------------------

    @app.get("/api/netmap")
    def network_map():
        """Topology of the Host, Its Networks, VMs and Containers as a Graph
        ---
        tags: [network]
        responses:
          200:
            description: Node and link graph, with a node per adapter
        description: >
          Read from the OS, VBoxManage and docker network inspect, with a live
          TCP probe per endpoint, so a node is up because it answered - not
          because a config file says so. Never 500s: a missing docker daemon
          or VBoxManage just yields fewer nodes.
          `virt` carries hypervisor auto-detection (VirtualBox, QEMU, VMware,
          Hyper-V) so the panel describes the host it is running on rather than
          assuming one vendor; `vbox` stays the VirtualBox-only detail.
        """
        try:
            return jsonify(netmap.snapshot())
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({"generated_at": None, "nodes": [], "links": [],
                            "counts": {}, "error": f"{type(exc).__name__}: {exc}"})

    return app


# Defined at module scope, not inside create_app(): create_app returns `app`
# here, so anything placed after it would be unreachable dead code nested in
# this function rather than a helper the route above can call.
#
# Every YAML fact below comes out of PyYAML - through python/panel/yamlview.py,
# which the analysis-configuration page shares, since it reads pipelines/*.yaml
# the same way the compose viewer reads a compose file.


def _compose_services(content: str) -> list[dict]:
    """Every service with its whole configuration.

    Not a fixed allowlist of keys: an allowlist silently drops whatever it does
    not name (profiles, cap_add, sysctls, ulimits, extra_hosts...), so the
    viewer would quietly under-report the file it claims to be showing.

    Deliberately a pure file read - no Docker, no live state. The Containers
    panel already polls runtime status and hands it to the viewer separately,
    so querying it here too would add a `docker stats` round trip to a click
    that only needs to read a file, and would make reading the compose file
    depend on the daemon being up.
    """
    try:
        document = yaml.safe_load(content)
    except yaml.YAMLError:
        return []
    if not isinstance(document, dict):
        return []
    services = document.get("services")
    if not isinstance(services, dict):
        return []
    out = []
    for name, config in services.items():
        if not isinstance(config, dict):
            continue
        out.append({"name": str(name), "config": _jsonable(config)})
    return out
