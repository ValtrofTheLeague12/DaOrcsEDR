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
import shutil
import tempfile
import threading
from pathlib import Path

import yaml
from flask import Flask, jsonify, make_response, request, send_file

from .analysis import analysis, analysis_settings, memory_profiling
from .analysis import cti_settings
from .artifacts import artifacts, share_settings
from .build import build, build_checks, hardening
from .clamd import clamd
from .core import auth, config, docs
from .core.yamlview import jsonable as _jsonable, spans as _yaml_spans
from .host import (containers, endpoints, launcher, logs, services, stats,
                   system, trace)
from .network import netmap, vms, vmmetrics
from .pipeline import pipeline_run
from .qiling import qiling
from .samples import (dynamic_analysis, sample_factory, sample_resources,
                      samples)
from .utils import password_generator, utils

try:
    from flasgger import Swagger
except ImportError:  # pragma: no cover - optional; the panel still runs without it
    Swagger = None

# Endpoints that must stay reachable without a session, or the UI can never log
# itself in.
_PUBLIC = {"/api/health", "/api/auth/state", "/api/auth/login"}


def create_app() -> Flask:
    app = Flask(__name__)
    artifact_restore_lock = threading.Lock()

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

    @app.post("/api/services/<key>/<action>")
    def control_service(key, action):
        """Start or Stop One of the Python Services
        ---
        tags: [services]
        parameters:
          - name: key
            in: path
            required: true
            type: string
            description: analyzer, malapi or ml
          - name: action
            in: path
            required: true
            type: string
            description: start or stop
        responses:
          200:
            description: Started, stopped, or already in that state
          400:
            description: Action is not start or stop
          404:
            description: Service has no start/stop rule
          409:
            description: Refused - blocked, port held, busy or nothing running
          502:
            description: Spawned but did not answer, or could not stop it
        description: >
          Only the three Python services the panel supervises have a rule:
          the Analyzer API, MalAPI and the ML scorer. Containers and VMs are
          controlled by their own routes, and any other key is a 404 before a
          process is considered - the allowlist lives in launcher.UNIT_KEYS,
          not in the URL.

          `start` waits for the endpoint the Services card actually probes, so
          a 200 means the card will be green on the next read, not merely that
          a process was forked. `stop` refuses to kill a listener whose command
          line does not look like that service, because a port being busy and a
          port being *ours* are different facts.
        """
        try:
            if action not in ("start", "stop"):
                return jsonify(ok=False, error="action must be start or stop",
                               code="bad-action", key=key, action=action), 400
            result = launcher.control(key, action)
        except launcher.ControlError as exc:
            return jsonify(ok=False, error=str(exc), code=exc.code,
                           key=key, action=action), exc.status
        return jsonify(result), launcher.HTTP_STATUS.get(result["code"], 200)

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
            description: Last N lines, preserving ANSI color sequences
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

    @app.get("/api/analysis/share-settings")
    def get_share_settings():
        """Public MEGA Link Settings
        ---
        tags: [analysis]
        responses:
          200:
            description: config/share.json's link expiry, with a summary and the
              duration units the UI offers
        description: >
          The expiry applied to public MEGA links the panel creates (Artifacts
          > Get MEGA link, and the end of an Export to MEGA job). A panel-owned
          setting: the analyzer never publishes a link, so this is not a key in
          config/analysis.yaml.

          An empty value means permanent links. A broken file is reported in
          `error` and makes link creation refuse rather than silently fall back
          to permanent.
        """
        return jsonify(share_settings.snapshot(config.REPO))

    @app.put("/api/analysis/share-settings")
    def put_share_settings():
        """Set or Clear the Public Link Expiry
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
                link_expire:
                  type: string
                  description: >
                    A MEGA time delay: s, M (minutes), h, d, m (months), y,
                    combinable, e.g. 12h or 1m12d3h. null or "" makes links
                    permanent.
        responses:
          200:
            description: The setting as it now stands on disk
          400:
            description: An unknown key or an invalid duration
          500:
            description: The file exists but could not be written
        description: >
          Applies when a link is created. An existing export keeps its expiry:
          MEGA cannot modify an export in place, so changing this does not
          rewrite links that are already out.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        try:
            result = share_settings.write(config.REPO, body)
        except ValueError as exc:
            return _bad(exc)
        except OSError as exc:
            return _bad(exc, 500)
        return jsonify(ok=True, share=result)

    @app.get("/api/analysis/memory-profiling")
    def get_memory_profiling():
        """Memory Profiling Option
        ---
        tags: [analysis]
        responses:
          200:
            description: >
              The stored option, the two targets, the files under the sample
              roots, VMMap and analyzer readiness, and the current or last
              profile job.
        description: >
          config/memory_profiling.json, a panel-owned setting. It is not a key
          in config/analysis.yaml because the analyzer's C++ reader rejects
          unknown keys there, and opening this page must not be able to stop
          the next analysis from starting.

          `vmmap` reports whether Sysinternals VMMap and the Windows analyzer
          executable are available.
        """
        try:
            return jsonify(memory_profiling.snapshot(config.REPO))
        except (ValueError, OSError) as exc:
            return _bad(exc, 400)

    @app.put("/api/analysis/memory-profiling")
    def put_memory_profiling():
        """Set the Memory Profiling Option
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
                enabled: {type: boolean}
                target:
                  type: string
                  enum: [analyzer, sample]
                sample:
                  type: string
                  description: Repo-relative sample path, for the sample target.
                keep_open:
                  type: boolean
                  description: >
                    Open the saved .mmp in VMMap's GUI after a successful
                    capture and leave the GUI running.
              example: {"enabled": true, "target": "analyzer", "keep_open": false}
        responses:
          200:
            description: The option as it now stands on disk
          400:
            description: A non-object body, an unknown key or an invalid value
        description: >
          Rewrites config/memory_profiling.json whole (temp + rename). The file
          is panel-owned, so this never touches config/analysis.yaml or a
          pipeline. Selecting a target does not start anything: the profile is
          an           explicit action, because profiling a full analysis can take
          minutes.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        try:
            result = memory_profiling.write(config.REPO, body)
        except ValueError as exc:
            return _bad(exc)
        except OSError as exc:
            return _bad(exc, 500)
        return jsonify(ok=True, settings=result,
                       snapshot=memory_profiling.snapshot(config.REPO))

    @app.post("/api/analysis/memory-profiling/run")
    def run_memory_profiling():
        """Start a Memory Profile
        ---
        tags: [analysis]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: false
            schema:
              type: object
              properties:
                target:
                  type: string
                  enum: [analyzer, sample]
                sample:
                  type: string
                  description: Repo-relative path under a sample root.
                timeout: {type: integer}
        responses:
          200:
            description: The profile job to poll
          400:
            description: A bad target, sample or timeout
          409:
            description: Another memory profile is already running
        description: >
          Starts the Windows analyzer or selected Windows executable and asks
          VMMap to save a process memory-map snapshot as a background job.
          Snapshots land under
          exports/memory_profiling/.
        """
        body = request.get_json(silent=True)
        if body is None:
            body = {}
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        result = memory_profiling.start(
            config.REPO,
            target=body.get("target"),
            sample=body.get("sample"),
            timeout=body.get("timeout"),
        )
        if not result.get("ok"):
            return jsonify(result), 409 if result.get("job_id") else 400
        return jsonify(result)

    @app.post("/api/analysis/memory-profiling/generated")
    def run_generated_memory_profiling():
        """Capture a VMMap snapshot of the generated Windows executable."""
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        result = memory_profiling.start_generated(
            config.REPO,
            executable=body.get("executable"),
            timeout=body.get("timeout"),
        )
        if not result.get("ok"):
            return jsonify(result), 409 if result.get("job_id") else 400
        return jsonify(result)

    @app.get("/api/analysis/memory-profiling/run/<job_id>")
    def memory_profiling_job(job_id: str):
        """Memory Profile Job
        ---
        tags: [analysis]
        parameters:
          - in: path
            name: job_id
            required: true
            type: string
        responses:
          200:
            description: The job's state, bounded log and output directory
          404:
            description: No such job (or it aged out)
        description: >
          Polled by the Analysis Configuration page while a profile runs. The
          job keeps its report directory on disk after the log
          scrollback is pruned, so a finished profile stays readable.
        """
        result = memory_profiling.job(job_id)
        if result is None:
            return jsonify(ok=False, error="no such memory-profile job"), 404
        return jsonify(ok=True, job=result)

    @app.get("/api/analysis/memory-profiling/run/<job_id>/layout")
    def memory_profiling_layout(job_id: str):
        """Return a parsed VMMap memory layout
        ---
        tags: [analysis]
        parameters:
          - in: path
            name: job_id
            required: true
            type: string
        responses:
          200:
            description: Category totals and nested process regions
          404:
            description: No such memory-profile job
          409:
            description: The CSV export is unavailable or invalid
        """
        result = memory_profiling.layout(job_id)
        if result is None:
            return jsonify(ok=False, error="no such memory-profile job"), 404
        if result.get("error"):
            return jsonify(ok=False, error=result["error"]), 409
        return jsonify(ok=True, layout=result["layout"])

    @app.get("/api/analysis/memory-profiling/run/<job_id>/snapshot")
    def memory_profiling_snapshot_file(job_id: str):
        """Download a native VMMap snapshot
        ---
        tags: [analysis]
        parameters:
          - in: path
            name: job_id
            required: true
            type: string
        responses:
          200:
            description: Native VMMap .mmp file
          404:
            description: No job or snapshot file exists
        """
        result = memory_profiling.job(job_id)
        if result is None:
            return jsonify(ok=False, error="no such memory-profile job"), 404
        path = memory_profiling.snapshot_file(job_id)
        if path is None:
            return jsonify(ok=False, error="the VMMap snapshot is not available"), 404
        return send_file(path, as_attachment=True,
                         download_name=f"vmmap-{job_id}.mmp",
                         mimetype="application/octet-stream")

    @app.get("/api/analysis/memory-profiling/run/<job_id>/csv")
    def memory_profiling_csv_file(job_id: str):
        """Download the VMMap CSV memory map
        ---
        tags: [analysis]
        parameters:
          - in: path
            name: job_id
            required: true
            type: string
        responses:
          200:
            description: VMMap CSV export, including the summary and address regions
          404:
            description: No job or CSV export exists
        """
        result = memory_profiling.job(job_id)
        if result is None:
            return jsonify(ok=False, error="no such memory-profile job"), 404
        path = memory_profiling.csv_file(job_id)
        if path is None:
            return jsonify(ok=False, error="the VMMap CSV export is not available"), 404
        return send_file(path, as_attachment=True,
                         download_name=f"vmmap-{job_id}.csv",
                         mimetype="text/csv")

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

    # --- the bundle-password resource ----------------------------------------
    #
    # The password lives in ONE file outside the repo (%APPDATA%\IAProject\
    # bundle-keys\upload.password, or IA_BUNDLE_PASSWORD_FILE), and these routes
    # manage that file: report on it, set an operator-chosen value, generate one
    # (value returned exactly once), or clear it. None of them accepts or
    # returns the value through any config write, and none will echo it again
    # after its one showing - a generated password that comes back on every
    # poll is not a secret, it is a page decoration.

    @app.get("/api/artifacts/bundle-password")
    def bundle_password_status():
        """Bundle Password Status
        ---
        tags: [artifacts]
        responses:
          200:
            description: Whether a password file exists and where it lives
        description: >
          The operator password file's STATE - present, and the path - for the
          Analysis Configuration page's status chip. The value itself is never
          in this response: a GET here runs on every poll, and a password that
          polls alongside the settings is not being kept.
        """
        return jsonify(ok=True, **analysis._bundle_password_status())

    @app.post("/api/artifacts/bundle-password")
    def bundle_password_set():
        """Set the Bundle Password
        ---
        tags: [artifacts]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                password: {type: string}
        responses:
          200:
            description: Stored under the operator password file
          400:
            description: Empty or too short (8 bytes is the floor)
        description: >
          Writes the operator's own password, byte-exact, into the password
          file outside the repo. The value is accepted once and never returned;
          the response is the same status shape the GET gives.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or "password" not in body:
            return jsonify(ok=False, error="body must be {'password': ...}"), 400
        result = analysis._bundle_password_set(body.get("password"))
        if not result.get("ok"):
            return jsonify(result), 400
        return jsonify(result)

    @app.post("/api/artifacts/bundle-password/generate")
    def bundle_password_generate():
        """Generate the Bundle Password
        ---
        tags: [artifacts]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            schema:
              type: object
              properties:
                length: {type: integer, description: "12-128 chars, default 24"}
                mode:
                  type: string
                  enum: [random, stale]
                  description: >
                    random = printable characters from a CSPRNG (default);
                    stale = words plus a random tag, easier to retype.
        responses:
          200:
            description: The generated value, this one time
          400:
            description: A length outside 12..128, or an unknown mode
        description: >
          Generates a password with the panel's PasswordGenerator (random or
          stale mode) under crypto-grade randomness, stores it in the password
          file, and returns it EXACTLY ONCE. The page shows it with a copy
          button while it is on screen and never again; there is no second
          read, and no recovery if it is lost without being stored somewhere
          real. That is the same trade every password here makes, said out
          loud instead of hidden.
        """
        body = request.get_json(silent=True) or {}
        result = analysis._bundle_password_generate(
            body.get("length", password_generator.DEFAULT_PASSWORD_LENGTH)
            if isinstance(body, dict) else password_generator.DEFAULT_PASSWORD_LENGTH,
            body.get("mode") if isinstance(body, dict) else None)
        if not result.get("ok"):
            return jsonify(result), 400
        return jsonify(result)

    @app.delete("/api/artifacts/bundle-password")
    def bundle_password_clear():
        """Clear the Bundle Password
        ---
        tags: [artifacts]
        responses:
          200:
            description: The password file is removed
        description: >
          Deletes the operator password file. Protection stays switchable, so
          this is not a dangerous act by itself - but an upload with MEGA_SEAL
          on and no password file now refuses to run, which is the fail-closed
          outcome the console keeps choosing.
        """
        result = analysis._bundle_password_clear()
        if not result.get("ok"):
            return jsonify(result), 400
        return jsonify(result)

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

          It edits the same inline `phases: [...]` lists, so the wizard
          preview, the planner and this control cannot
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

    @app.get("/api/threat-intelligence/apis")
    def threat_intelligence_api_settings():
        """Static Analyzer Threat-Intelligence Provider Status
        ---
        tags: [threat-intelligence]
        responses:
          200:
            description: Provider metadata and saved-key state; secret values are never returned
          500:
            description: CTI settings could not be read
        """
        try:
            return jsonify(cti_settings.status())
        except cti_settings.CTISettingsError as exc:
            return jsonify(error=str(exc)), 500

    @app.put("/api/threat-intelligence/apis")
    def update_threat_intelligence_api_settings():
        """Save or Clear Static Analyzer Provider API Keys
        ---
        tags: [threat-intelligence]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [keys]
              properties:
                keys:
                  type: object
                  description: Provider ID to key text; null explicitly clears a saved key
        responses:
          200:
            description: Updated provider status without returning credential values
          400:
            description: Invalid provider or key value
          500:
            description: Settings could not be saved securely
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or "keys" not in body:
            return jsonify(error="request must contain a keys object"), 400
        try:
            return jsonify(cti_settings.update(body["keys"]))
        except cti_settings.CTISettingsError as exc:
            return jsonify(error=str(exc)), 400
        except (OSError, subprocess.SubprocessError):
            return jsonify(error="CTI settings could not be saved securely"), 500

    @app.get("/api/artifacts/settings")
    def artifact_settings():
        """Effective MEGA settings used by the Artifacts dashboard
        ---
        tags: [artifacts]
        responses:
          200:
            description: Effective upload settings, destination and password state
        description: >
          Reads only the artifact settings; it does not resolve or launch the
          analyzer's phase catalog. The Artifacts page uses this lightweight
          endpoint so MEGA settings do not wait on unrelated pipeline metadata.
        """
        return jsonify(analysis.artifact_settings())

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
          the archive, its recorded digest and whether re-hashing it
          agrees. `remote` is the same bundles read back off MEGA through
          mega/list.py, and `transfer` is the effective throughput between
          consecutive uploads.

          Listing remains read-only. Uploading stays a CLI action
          (`python mega/upload.py --artifact <name>`); an explicit recovery
          action is available separately for downloading and verifying an
          existing remote bundle.

          The remote half is a third-party call and refreshes in the background,
          so a slow MEGA cannot hold the page request open. While it runs,
          `remote.refreshing` is true and the page polls for the result.
          MEGAcmd missing, no session and timeout degrade to `available: false`
          with a reason; a truncated answer says so instead of looking complete.

          The rate is an upper bound, not a measured line rate: MEGAcmd records
          when an upload finished and nothing records when it started, so the
          interval between two bundles includes however long the operator
          waited before pressing upload.

          Cached for 5 minutes, because nothing writes to MEGA on a timer.
          `?refresh=1` bypasses both caches so the Rescan button reflects an
          upload that just happened rather than one from five minutes ago.
        """
        try:
            remote_root = request.args.get("remote_root")
            if remote_root is None:
                remote_root = analysis.artifact_remote_root()
            return jsonify(artifacts.snapshot(
                remote_root,
                request.args.get("refresh") == "1",
                background_remote=True,
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

    @app.post("/api/artifacts/restore")
    def artifact_restore():
        """Verify and Extract a Recovered Evidence Bundle
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
        responses:
          200:
            description: Bundle verified and extracted
          400:
            description: Invalid artifact name
          404:
            description: The local bundle has not been recovered
          409:
            description: A restored copy already exists or another restore is running
          502:
            description: Verification or extraction failed
          504:
            description: Extraction exceeded its time limit
        description: >
          Uses mega/restore.py's local verify-only path, so the digest is checked
          before extraction and archive members are checked for traversal. The
          restored tree is moved into exports/<name>_recovered only after the
          script succeeds; partial output stays in a temporary directory.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="request body must be a JSON object"), 400
        raw_name = body.get("name")
        if not isinstance(raw_name, str):
            return jsonify(ok=False, error="artifact name must be a string"), 400
        name = raw_name.strip()
        if not artifacts.valid_name(name):
            return jsonify(ok=False, error="invalid artifact name"), 400
        if not artifact_restore_lock.acquire(blocking=False):
            return jsonify(ok=False, error="another artifact restore is running"), 409

        staging = None
        try:
            exports = (config.REPO / "exports").resolve()
            bundle = (exports / f"{name}{artifacts.BUNDLE_SUFFIX}").resolve()
            try:
                bundle.relative_to(exports)
            except ValueError:
                return jsonify(ok=False, error="invalid artifact path"), 400
            if not artifacts.local_archive(name) or not bundle.is_dir():
                return jsonify(ok=False, error="local evidence bundle not found; recover it first"), 404

            destination = exports / f"{name}_recovered"
            if destination.exists():
                return jsonify(ok=False, error="a restored copy already exists"), 409

            exports.mkdir(parents=True, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix=f".{name}-restore-", dir=exports))
            command = [
                sys.executable,
                str(config.REPO / "mega" / "restore.py"),
                "--verify-only",
                "--bundle", str(bundle),
                "--artifact", name,
                "--dest", str(staging),
            ]
            try:
                result = subprocess.run(
                    command,
                    cwd=config.REPO,
                    capture_output=True,
                    text=True,
                    timeout=1800,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return jsonify(ok=False, error="bundle verification and extraction timed out"), 504
            except OSError as exc:
                return jsonify(ok=False, error=f"could not start bundle restore: {exc}"), 502

            if result.returncode != 0:
                detail = (result.stderr or result.stdout).strip()
                return jsonify(
                    ok=False,
                    error=detail[-4000:] or f"bundle restore failed (exit {result.returncode})",
                ), 502
            if destination.exists():
                return jsonify(ok=False, error="a restored copy appeared during extraction"), 409
            staging.rename(destination)
            staging = None
            return jsonify(
                ok=True,
                name=name,
                directory=str(destination),
                detail=(result.stdout or "Bundle verified and extracted.").strip()[-4000:],
            )
        finally:
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)
            artifact_restore_lock.release()

    @app.get("/api/artifacts/local/<name>/evidence")
    def artifact_evidence_files(name: str):
        """List Files in a Verified, Restored Evidence Bundle
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
            description: Relative file paths and sizes in the restored evidence tree
          400:
            description: Invalid artifact name
          404:
            description: No restored evidence tree exists
        description: >
          Lists only regular files beneath exports/<name>_recovered. Paths are
          relative and are served through the matching evidence-file route,
          which checks containment again before opening a file.
        """
        if not artifacts.valid_name(name):
            return jsonify(ok=False, error="invalid artifact name"), 400
        exports = (config.REPO / "exports").resolve()
        root = (exports / f"{name}_recovered").resolve()
        try:
            root.relative_to(exports)
        except ValueError:
            return jsonify(ok=False, error="invalid artifact path"), 400
        if not root.is_dir():
            return jsonify(ok=False, error="restored evidence not found"), 404

        files = []
        truncated = False
        for path in sorted(root.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                resolved = path.resolve()
                resolved.relative_to(root)
                relative = path.relative_to(root).as_posix()
                size = resolved.stat().st_size
            except (OSError, ValueError):
                continue
            if len(files) >= 5000:
                truncated = True
                break
            files.append({
                "path": relative,
                "bytes": size,
                "html": path.suffix.lower() in (".html", ".htm"),
                "url": f"/api/artifacts/local/{name}/evidence/{relative}",
            })
        return jsonify(name=name, directory=str(root), files=files, truncated=truncated)

    @app.get("/api/artifacts/local/<name>/evidence/<path:relative_path>")
    def artifact_evidence_file(name: str, relative_path: str):
        """Open a File from a Restored Evidence Bundle
        ---
        tags: [artifacts]
        parameters:
          - name: name
            in: path
            required: true
            type: string
          - name: relative_path
            in: path
            required: true
            type: string
        responses:
          200:
            description: Evidence file; HTML reports are sandboxed by response policy
          400:
            description: Invalid artifact name or relative path
          404:
            description: Evidence file not found
        description: >
          A client path is accepted only when its resolved target remains under
          the selected restored evidence directory. HTML is rendered with a
          restrictive CSP sandbox: inline report scripts may run, but network
          access, forms, plugins and parent-origin access are blocked.
        """
        if not artifacts.valid_name(name):
            return jsonify(ok=False, error="invalid artifact name"), 400
        relative = Path(relative_path)
        if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
            return jsonify(ok=False, error="invalid evidence path"), 400
        exports = (config.REPO / "exports").resolve()
        root = (exports / f"{name}_recovered").resolve()
        candidate = root / relative
        if candidate.is_symlink():
            return jsonify(ok=False, error="evidence file not found"), 404
        target = candidate.resolve()
        try:
            root.relative_to(exports)
            target.relative_to(root)
        except ValueError:
            return jsonify(ok=False, error="invalid evidence path"), 400
        if not target.is_file():
            return jsonify(ok=False, error="evidence file not found"), 404

        response = send_file(target, as_attachment=False, conditional=True)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        if target.suffix.lower() in (".html", ".htm"):
            response.headers["Content-Security-Policy"] = (
                "sandbox allow-scripts; default-src 'none'; "
                "script-src 'unsafe-inline'; style-src 'unsafe-inline' data:; "
                "img-src 'self' data: blob:; font-src data:; connect-src 'none'; "
                "object-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'"
            )
        return response

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
        if (not remote_root or remote_root.startswith("-")
                or "\\" in remote_root or "\x00" in remote_root
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
            description: the effective upload toggle is off (MEGA_UPLOAD wins
              over upload_artifacts; see the Analysis Configuration page)
          404:
            description: No local bundle with that name
        description: >
          The mirror of recovery: pushes a bundle that is on disk up to MEGA
          through mega/upload.py, which is the same script and the same
          determinism guarantees an operator gets from the CLI.

          Returns a job handle immediately - sealing a large bundle and pushing
          it over a consumer link takes minutes, and the log is the useful part.
          Poll GET /api/artifacts/export/<job_id>.

          Gated on the effective upload toggle: analysis.yaml's MEGA_UPLOAD
          wins over config/artifacts.yaml's upload_artifacts. That setting is
          the operator saying this lab does not send evidence off the host, and
          a button in a browser has to honour it exactly as the analyzer does.
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

    @app.post("/api/artifacts/link")
    def artifact_link():
        """Get or Create a Public MEGA Link for a Remote Bundle
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
            description: The public link, clickable in a browser
          400:
            description: Invalid artifact name or MEGA root
          404:
            description: The bundle is not on MEGA under that root
          502:
            description: MEGAcmd could not create or read the link
          503:
            description: MEGAcmd is missing or has no session
        description: >
          Returns the bundle folder's public https://mega.nz link, creating the
          export if it does not exist yet. The URL carries MEGA's decryption key
          in its fragment, so it is the whole capability: when the bundle was
          not password-protected, anyone who receives it can download the
          evidence. The page shows it with a copy button for that reason.

          The links are also attached to GET /api/artifacts bundles that were
          already exported; this route exists for bundles that were not, and for
          the explicit "share this" action.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        raw_name = body.get("name")
        if not isinstance(raw_name, str):
            return jsonify(ok=False, error="artifact name must be a string"), 400
        result = artifacts.link_for(raw_name.strip(),
                                    str(body.get("remote_root") or "/"))
        if result.get("ok"):
            return jsonify(result)
        error = str(result.get("error") or "")
        if error.startswith("invalid"):
            status = 400
        elif "not on MEGA" in error:
            status = 404
        elif "MEGAcmd" in error or "session" in error:
            status = 503
        else:
            status = 502
        return jsonify(result), status


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
          optional: the analysis settings say MEGA_UPLOAD: true, so without it
          a test started from a browser button would push an evidence bundle to
          the operator's cloud account.
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

    # --- build: hardening - the settings, and what the binary actually carries --

    @app.get("/api/build/hardening")
    def build_hardening():
        """Binary Hardening: the requested settings and the carried facts
        ---
        tags: [build]
        responses:
          200:
            description: The four protection settings, and whether the built
                         binary carries them
        description: >
          Two halves in one payload, because the card that shows them answers
          one question - "do the settings and the binary agree?" - and a page
          that fetched them separately could render the requested settings
          beside a binary built before they were written.

          The settings half is config/hardening.json: four Windows protections
          (ASLR, high-entropy VA, DEP/NX, stack protector), each ON by default
          because MinGW's linker and compiler already default them on. The
          switches exist to turn a protection OFF deliberately, so the file
          records the intent and a build started from the panel and one started
          from a terminal produce the same binary.

          The compliance half reads the finished executable: three PE-header
          bits (DllCharacteristics) and the canary runtime for the stack
          protector, which has no header bit and is therefore a weaker signal
          - the report says how each fact was determined rather than presenting
          the inference as a header fact.

          Reading the binary streams it once; the call is made on page load and
          after a build, not on a fast poll.
        """
        return jsonify({
            "settings": hardening.snapshot(config.REPO),
            "compliance": hardening.compliance(config.REPO, build_checks.EXE),
        })

    @app.put("/api/build/hardening")
    def build_hardening_set():
        """Set Binary Hardening
        ---
        tags: [build]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              additionalProperties:
                type: boolean
                description: Protection name to whether the NEXT build asks for it
              example: {"aslr": true, "stack_protector": false}
        responses:
          200:
            description: The settings as they now stand, and the compliance report
          400:
            description: A non-object body, an unknown key, or a non-boolean value
        description: >
          Rewrites only the keys present in the body; the rest keep their
          current value. The file is rewritten whole (temp + rename) rather
          than patched in place: it is four booleans, and a half-written
          settings file is a worse lie than no file.

          Values are validated strictly - `true`/`false` only. A stringified
          `"false"` is refused rather than accepted, because a client that
          stringified its payload must never silently flip a protection OFF,
          which is the one accident this whole mechanism exists to prevent. An
          unknown key is refused too: it means the file was written by a
          different version of this project, and the operator's intent is not
          being honoured.

          Takes effect at the next build - build.ps1 reads the file when it
          runs. The returned compliance report still describes the CURRENT
          binary, so a mismatch after the write is the expected "rebuild"
          state, not an error.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        try:
            hardening.write(config.REPO, body)
        except ValueError as exc:
            return _bad(exc)
        except OSError as exc:
            return _bad(exc, 500)
        return jsonify({
            "settings": hardening.snapshot(config.REPO),
            "compliance": hardening.compliance(config.REPO, build_checks.EXE),
        })

    @app.get("/api/dynamic-analysis/config")
    def dynamic_analysis_config():
        """Dynamic Analysis Configuration - one transport choice
        ---
        tags: [dynamic-analysis]
        responses:
          200:
            description: The stored policy, the two options, and the file path
        description: >
          config/dynamic_analysis.json holds ONE choice for how a sample under
          dynamic analysis is allowed to communicate:

            tcp   the guest keeps a routable virtual NIC and may open sockets
            sftp  the guest is driven over SSH/SFTP and the sample gets no raw
                  TCP path out

          A radio rather than two checkboxes because the two are not additive:
          "network on AND SFTP" has two answers depending on which path the
          sample took, and nobody can say which one a run used.

          The file lives beside the other panel-owned JSON config rather than in
          config/analysis.yaml: the analyzer's C++ reader treats an unknown key
          there as a hard error, and this setting belongs to the dynamic side.
        """
        return jsonify(dynamic_analysis.snapshot(config.REPO))

    @app.put("/api/dynamic-analysis/config")
    def dynamic_analysis_config_set():
        """Set the Dynamic Analysis Transport
        ---
        tags: [dynamic-analysis]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                communication:
                  type: string
                  enum: [tcp, sftp]
                  description: The transport every dynamic analysis may use
              example: {"communication": "sftp"}
        responses:
          200:
            description: The policy as it now stands
          400:
            description: A non-object body, an unknown key, or an unknown id
        description: >
          Rewrites the file whole (temp + rename). The value is validated against
          the two ids the page offers - an unknown string is refused, not stored,
          because a typo in the file would otherwise silently select a transport
          that no code path implements.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(ok=False, error="body must be a JSON object"), 400
        try:
            dynamic_analysis.write(config.REPO, body)
        except ValueError as exc:
            return _bad(exc)
        except OSError as exc:
            return _bad(exc, 500)
        return jsonify(dynamic_analysis.snapshot(config.REPO))

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

    # --- generator resources (value pools for the sample factory) --------------

    @app.get("/api/utils/resources")
    def utils_resources():
        """Generator Resources
        ---
        tags: [utils]
        responses:
          200:
            description: The pools, their sources and the factory features
                         each one can honour
        description: >
          Value pools the Build page's sample factory draws from: malicious IPs,
          domains, URLs and file hashes. Definitions live in
          config/sample_resources.json; fetched values live in the panel's
          cache and never in git.

          These are bait literals, not detection knowledge - the factory copies
          a sampled value into a generated C/C++ source, and nothing is dialled.

          Every resource reports its last good fetch AND its last failed one.
          A failed refresh keeps the previous values rather than emptying a pool
          the factory depends on.
        """
        return jsonify(sample_resources.snapshot())

    @app.post("/api/utils/resources")
    def utils_resource_add():
        """Add a Generator Resource
        ---
        tags: [utils]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [label, kind, url]
              properties:
                label: {type: string}
                kind: {type: string, enum: [ip, domain, url, hash]}
                url:
                  type: string
                  description: >
                    Any http(s) URL. A github.com /blob/ page is rewritten to
                    the raw URL the panel actually fetches.
                enabled: {type: boolean, default: true}
                note: {type: string}
                fetch:
                  type: boolean
                  default: true
                  description: Fetch the values immediately after adding.
        responses:
          200: description: New snapshot, plus what the first fetch found
          400: description: Invalid field, URL, kind or duplicate id
          503: description: The definitions file could not be written
        description: >
          Adding a resource does not make its values available: they appear only
          after a successful fetch. `fetch` defaults to true so the usual case -
          paste a URL, get a pool - is one press; a failed first fetch is
          reported inside `refresh` and the resource stays configured with the
          error attached.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "body must be a JSON object"}), 400
        body = dict(body)
        fetch = body.pop("fetch", True)
        if not isinstance(fetch, bool):
            return jsonify({"ok": False, "error": "'fetch' must be a boolean"}), 400
        try:
            record = sample_resources.add(body)
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except OSError as exc:
            return jsonify({"ok": False,
                            "error": f"could not write the resources file: {exc}"}), 503
        refresh = sample_resources.refresh(record["id"]) if fetch else None
        return jsonify({"ok": True, "added": record["id"], "refresh": refresh,
                        **sample_resources.snapshot()})

    @app.put("/api/utils/resources/<resource_id>")
    def utils_resource_update(resource_id: str):
        """Edit a Generator Resource
        ---
        tags: [utils]
        consumes: [application/json]
        parameters:
          - in: path
            name: resource_id
            required: true
            type: string
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                label: {type: string}
                kind: {type: string, enum: [ip, domain, rot13, xor]}
                url: {type: string}
                enabled: {type: boolean}
                note: {type: string}
        responses:
          200: description: New snapshot
          400: description: Invalid field or value
          404: description: No resource with that id
        description: >
          Changing the URL or kind drops the cached values: yesterday's list
          must not answer for the new address under a new label. The resource
          then reads as "not fetched" until it is refreshed.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "body must be a JSON object"}), 400
        try:
            sample_resources.update(resource_id, body)
        except LookupError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 404
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except OSError as exc:
            return jsonify({"ok": False,
                            "error": f"could not write the resources file: {exc}"}), 503
        return jsonify({"ok": True, **sample_resources.snapshot()})

    @app.delete("/api/utils/resources/<resource_id>")
    def utils_resource_remove(resource_id: str):
        """Remove a Generator Resource
        ---
        tags: [utils]
        parameters:
          - in: path
            name: resource_id
            required: true
            type: string
        responses:
          200: description: New snapshot (the cache entry is deleted too)
          404: description: No resource with that id
        description: >
          Removes the definition AND its cached values. A factory feature whose
          last pool disappears stops being offered, with the reason shown on
          both pages.
        """
        try:
            sample_resources.remove(resource_id)
        except LookupError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 404
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        except OSError as exc:
            return jsonify({"ok": False,
                            "error": f"could not write the resources file: {exc}"}), 503
        return jsonify({"ok": True, **sample_resources.snapshot()})

    @app.post("/api/utils/resources/<resource_id>/refresh")
    def utils_resource_refresh(resource_id: str):
        """Fetch a Generator Resource Now
        ---
        tags: [utils]
        parameters:
          - in: path
            name: resource_id
            required: true
            type: string
        responses:
          200:
            description: Snapshot plus the fetch result. `ok` describes THIS
                         fetch - a failed one still returns 200 so the page can
                         show the error beside the last good values.
        description: >
          Downloads the resource's URL and validates every line for its kind.
          A body that is not UTF-8 text, is over 16 MiB, redirects to a
          non-http(s) scheme, or yields no usable values is refused with a
          sentence; the previous good cache stays in place and keeps feeding
          the factory.
        """
        result = sample_resources.refresh(resource_id)
        return jsonify({"ok": result.get("ok", False),
                        **sample_resources.snapshot(), "refresh": result})

    @app.post("/api/build")
    def build_start():
        """Build the Analyzer
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

    # --- pipeline runs (watch the analyzer on a chosen sample) ----------------

    @app.get("/api/pipeline-run")
    def pipeline_run_current():
        """The Pipeline Run Watcher
        ---
        tags: [build]
        responses:
          200:
            description: The run in progress, or the most recent one, or null
        description: >
          One poll for the whole feature: while a run is live this is its state
          and log; after it finishes the same view stays readable until
          something replaces it, which is what lets a reload land back on the
          output instead of an empty panel.

          A run that was ended by its duration limit reports
          `state: "stopped"` with `timed_out: true`, rather than the `"failed"`
          a non-zero exit would otherwise imply - the clock ended it, not the
          analyzer.
        """
        return jsonify(pipeline_run.current())

    @app.post("/api/pipeline-run")
    def pipeline_run_start():
        """Run a Pipeline Now
        ---
        tags: [build]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [pipeline, sample]
              properties:
                pipeline: {type: string}
                sample: {type: string}
                duration:
                  type: integer
                  minimum: 10
                  maximum: 86400
                  description: >
                    Maximum seconds before the run is killed. Omit for no limit.
                allow_packed:
                  type: boolean
                  description: >
                    The explicit packed override. Omit (or false) and a packed
                    sample is refused with `code: "sample-packed"`; true is a
                    deliberate decision to run it anyway, and is logged.
        responses:
          200:
            description: Run started
          400:
            description: Refused, with the reason and a machine-readable `code`
          409:
            description: A run is already in progress
        description: >
          Starts `static_analyzer --no-curses --pipeline <name> <sample>` as a
          job whose output streams to the page.

          `sample` is a path relative to the repo root or absolute, and is
          validated before anything is spawned: an allowed executable
          extension (.exe, .dll, .bin, .sys), no '..' segments, no Win32 name
          tricks, and a resolved path inside the repo's sample roots
          (samples/, tests/fixtures/, exports/). The pipeline must exist on
          disk (or be the built-in `default`), and each refusal names the
          file or rule it refused.

          A packed sample (UPX markers, or whole-file entropy at the
          analyzer's own threshold) is refused with `code: "sample-packed"`
          before the analyzer is spawned - a run spent in unpacking loops is
          a run whose later phases cannot be trusted. `allow_packed: true`
          is the explicit override, and the response then carries the
          verdict under `packed`.

          `duration` bounds the run: on expiry the analyzer is terminated and
          SIGKILLed if it does not exit, and the job is marked `stopped` with
          `timed_out: true`. Omit it for an unbounded run, which is the default
          - a watchdog that armed itself would kill long runs nobody asked to
          bound. The minimum is 10s and the maximum 24h; anything else is
          refused rather than clamped, so the number the page shows back is the
          number that was asked for.

          IA_ARTIFACT_UPLOAD=0 is forced on every child, exactly as the Tests
          section does: a browser button must not push the evidence bundle to
          the operator's cloud account. Artifacts upload from the Artifacts
          page, on purpose.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "body must be a JSON object"}), 400
        pipeline = body.get("pipeline")
        sample = body.get("sample")
        if not isinstance(pipeline, str):
            return jsonify({"ok": False, "error": "'pipeline' must be a string"}), 400
        if not isinstance(sample, str):
            return jsonify({"ok": False, "error": "'sample' must be a string"}), 400
        # Passed through as-is; pipeline_run validates it and names the problem.
        # `None` is the documented "no limit", so an absent key and an explicit
        # null mean the same thing. The packed override is strict: only an
        # explicit true overrides, so `1` or "yes" from a sloppy client does
        # not silently become permission to run a packed executable.
        result = pipeline_run.start(pipeline.strip(), sample.strip(),
                                    body.get("duration"),
                                    allow_packed=body.get("allow_packed") is True)
        if result.get("ok"):
            return jsonify(result)
        return jsonify(result), 409 if result.get("code") == "already-running" else 400

    @app.post("/api/pipeline-run/<job_id>/stop")
    def pipeline_run_stop(job_id: str):
        """Stop a Pipeline Run
        ---
        tags: [build]
        parameters:
          - in: path
            name: job_id
            required: true
            type: string
        responses:
          200:
            description: Stop requested; the run ends when the child exits
          409:
            description: The run is not running, or the id is unknown
        description: >
          terminate(), recorded in the log with who asked, and the lines the
          analyzer already produced stay on the page. A kill button that
          wiped the log would destroy the only part worth keeping.

          If the analyzer does not exit within a short grace period it is then
          killed outright (SIGKILL on POSIX, TerminateProcess on Windows), so a
          wedged run cannot ignore the request. The job ends in state
          `"stopped"` rather than `"failed"`: a person asked, and the analyzer
          did not fail.
        """
        result = pipeline_run.stop(job_id)
        if result.get("ok"):
            return jsonify(result)
        return jsonify(result), 409

    @app.get("/api/build/samples")
    def sample_list():
        """List Samples
        ---
        tags: [build]
        responses:
          200:
            description: >
              Every analysable file directly under the repo's sample roots,
              newest first, plus the upload size cap
        description: >
          The Run a pipeline picker's choices. Only files inside
          config.SAMPLE_ROOTS (samples/, tests/fixtures/, exports/) with an
          allowed executable extension are listed; the run gate re-validates
          the chosen path anyway, so this listing is convenience rather than
          authority. Metadata only - no packed verdicts, because computing one
          reads each file whole. The selected file is inspected separately.
        """
        return jsonify(samples.list_samples())

    @app.post("/api/build/samples/upload")
    def sample_upload():
        """Upload a Sample
        ---
        tags: [build]
        consumes: [multipart/form-data]
        parameters:
          - in: formData
            name: file
            required: true
            type: file
            description: The executable to admit into samples/
          - in: formData
            name: allow_unscanned
            required: false
            type: boolean
            description: >
              Admit the file when clamd is unreachable. Explicit and logged;
              omitted means an unreachable scanner refuses the upload.
        responses:
          200:
            description: The file was admitted into samples/ and recorded in the manifest
          400:
            description: >
              Refused with a machine-readable `code` (bad-name, bad-extension,
              exists, scan-infected, scan-unavailable, no-file)
          413:
            description: The upload exceeds SAMPLE_UPLOAD_MAX_BYTES
        description: >
          The picker's upload route, backed by samples.save_upload(): the
          client's file name is a NAME only, the body is streamed to staging
          with the size cap enforced as it is written, clamd scans it, an
          infected file is quarantined as evidence, and an existing name is
          refused rather than overwritten. Only a file that survives every
          step lands in samples/, where the picker offers it. The run gate
          still validates that path before anything is spawned.
        """
        upload = request.files.get("file")
        if upload is None or not (upload.filename or "").strip():
            return jsonify({"ok": False, "code": "no-file",
                            "error": "send multipart/form-data with a 'file' "
                                     "field naming the executable"}), 400
        allow_unscanned = request.form.get("allow_unscanned", "").strip().lower() \
            in ("1", "true", "yes", "on")
        result = samples.save_upload(upload.filename, upload.stream,
                                     allow_unscanned=allow_unscanned)
        if result.get("ok"):
            return jsonify(result)
        return jsonify(result), 413 if result.get("code") == "too-large" else 400

    @app.post("/api/build/samples/inspect")
    def sample_inspect():
        """Inspect a Sample Path
        ---
        tags: [build]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required: [path]
              properties:
                path: {type: string}
        responses:
          200:
            description: >
              The sample's metadata - resolved path, size, mtime - plus the
              packed verdict and the state of the analyzer's own packed stop
          400:
            description: >
              The path was refused; the reason names the rule (extension,
              traversal, containment, existence)
        description: >
          Validates a typed sample path with the SAME rules the run gate
          applies - python/panel/samples/samples.py is the one implementation - and
          returns what the file is: size, mtime, and a packed verdict (UPX
          markers first, else whole-file entropy at the analyzer's own
          threshold). The Build page calls this before enabling Run, so a
          packed sample is stopped at selection rather than at start, and a
          path the page shows as valid is a path the gate will accept.

          The verdict is computed here, never taken from the client: the page
          displays it, the gate re-derives it.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or not isinstance(body.get("path"), str):
            return jsonify({"ok": False,
                            "error": "body must be a JSON object with a "
                                     "string 'path'"}), 400
        result = samples.meta(body["path"].strip())
        if result.get("ok"):
            return jsonify(result)
        return jsonify(result), 400

    # --- test-sample factory (compose a bait sample, compile it) ---------------

    @app.get("/api/build/sample/templates")
    def sample_factory_templates():
        """Sample Factory Templates
        ---
        tags: [build]
        responses:
          200:
            description: Languages, checkboxes, presets and the compiler state
        description: >
          What the Build page's sample factory offers: the two languages (C,
          C++), the checkbox vocabulary with one honest description of what
          each one does to the source, the preset bundles that bundle them,
          and whether the UCRT64 compiler the factory compiles through was
          found. Checked once per visit, like the test catalogue.
        """
        return jsonify(sample_factory.templates())

    @app.post("/api/build/sample/preview")
    def sample_factory_preview():
        """Preview a Composed Sample
        ---
        tags: [build]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                language: {type: string}
                template: {type: string}
                features: {type: array, items: {type: string}}
                encoding: {type: string, enum: [mixed, plain, rot13, xor, base64, chained]}
                sleep_seconds: {type: integer, minimum: 0, maximum: 3600}
                seed: {type: integer, minimum: 0, maximum: 4294967295}
                n_math: {type: integer, minimum: 0, maximum: 8}
                n_vars: {type: integer, minimum: 0, maximum: 24}
                loop_count: {type: integer, minimum: 0, maximum: 100}
                loop_step: {type: integer, minimum: 1, maximum: 10}
                loop_break_at: {type: integer, minimum: 0, maximum: 24}
                instruction_count: {type: integer, minimum: 1, maximum: 12}
                alloc_size: {type: integer, minimum: 1, maximum: 1048576}
                n_frees: {type: integer, minimum: 2, maximum: 8}
        responses:
          200:
            description: The composed source and the noise it carries
          400:
            description: Refused, with the reason
        description: >
          Returns the exact source text a press of Generate would produce -
          the noise IP and domain are drawn HERE, not at generate time, so the
          preview cannot differ from the artefact. The response carries the
          32-bit seed it drew with; sending that seed back replays the same
          sampled values and encodings. Nothing is written and nothing is
          compiled: this is checkable text in a code block. The encoding
          applies to the resource-backed IOCs; ROT13/XOR/BASE64 string
          checkboxes always carry their own encoding.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "body must be a JSON object"}), 400
        result = sample_factory.compose(
            body.get("language") or "",
            body.get("template"),
            body.get("features") if isinstance(body.get("features"), list) else [],
            body.get("encoding"),
            body.get("sleep_seconds"),
            body.get("seed"),
            body.get("n_math"),
            body.get("n_vars"),
            body.get("loop_count"),
            body.get("loop_step"),
            body.get("loop_break_at"),
            body.get("instruction_count"),
            body.get("alloc_size"),
            body.get("n_frees"))
        return (jsonify(result), 200 if result.get("ok") else 400)

    @app.post("/api/build/sample")
    def sample_factory_generate():
        """Generate a Sample From the Factory
        ---
        tags: [build]
        consumes: [application/json]
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                language: {type: string}
                template: {type: string}
                features: {type: array, items: {type: string}}
                name: {type: string}
                encoding: {type: string, enum: [mixed, plain, rot13, xor, base64, chained]}
                sleep_seconds: {type: integer, minimum: 0, maximum: 3600}
                upx: {type: boolean}
                virtualize: {type: boolean}
                makefile: {type: boolean}
                seed: {type: integer, minimum: 0, maximum: 4294967295}
                n_math: {type: integer, minimum: 0, maximum: 8}
                n_vars: {type: integer, minimum: 0, maximum: 24}
                loop_count: {type: integer, minimum: 0, maximum: 100}
                loop_step: {type: integer, minimum: 1, maximum: 10}
                loop_break_at: {type: integer, minimum: 0, maximum: 24}
                instruction_count: {type: integer, minimum: 1, maximum: 12}
                alloc_size: {type: integer, minimum: 1, maximum: 1048576}
                n_frees: {type: integer, minimum: 2, maximum: 8}
        responses:
          200:
            description: Compiled - source path, exe path, size, compile log
          400:
            description: Refused, with the reason and the compile log
        description: >
          Writes the composed source to samples/ and compiles it with the
          UCRT64 compiler the analyzer itself is built with (statically, so
          the bait runs wherever the run card points at it, free of the
          sysroot's DLLs). The returned paths are repo-relative. Optional
          post-compile steps: UPX packing with the in-tree upx/upx.exe, and
          Instruction Virtualisation through the in-tree EagleVM (virtualize).
          The latter compiles with the stub markers, runs EagleVM.exe, copies
          EagleVMStub.dll beside the result and returns the *_protected.exe -
          it refuses, naming the Utils build button, when EagleVM is not built.
          Sending the preview's seed composes the same sample
          the code block showed. The noise feature plants a TEST-NET-3 IP and a
          known benign domain - bait for the IOC and CTI layers that provably
          never dials anything. `makefile` writes samples/<name>.mk beside the
          source, before compiling, so the recipe survives a failed build.
        """
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "body must be a JSON object"}), 400
        result = sample_factory.generate(
            body.get("language") or "",
            body.get("template"),
            body.get("features") if isinstance(body.get("features"), list) else [],
            body.get("name") if isinstance(body.get("name"), str) else "",
            body.get("encoding"),
            body.get("sleep_seconds"),
            body.get("upx", False),
            body.get("virtualize", False),
            body.get("seed"),
            body.get("makefile", False),
            body.get("n_math"),
            body.get("n_vars"),
            body.get("loop_count"),
            body.get("loop_step"),
            body.get("loop_break_at"),
            body.get("instruction_count"),
            body.get("alloc_size"),
            body.get("n_frees"))
        return (jsonify(result), 200 if result.get("ok") else 400)


    # --- clamav (guest on the Qiling VM) -------------------------------------

    @app.get("/api/clamd/status")
    def clamd_status():
        """Service Status for the Transport in config/dynamic_analysis.json
        ---
        tags: [clamav]
        responses:
          200:
            description: >-
              Check results for the SELECTED transport, even when nothing
              answered. `communication.mode` is the choice, `communication.path`
              is the file it came from, and `communication.error` is set when
              that file could not be read.
        description: >
          Read-only, and transport-aware. The transport is read from
          config/dynamic_analysis.json - the same file the Dynamic Analysis
          page writes - and nothing here SSHes into the VM or starts a scan.

          When SFTP is selected the checks are the driver files in
          python/clamd/: scan_remote.py, clamd-python.py, vm_info.json and
          paramiko. No SSH session is opened; a status poll must stay cheap.

          When TCP is selected the checks go through
          panel/utils/socket_validator.py, which opens the socket the transport
          actually dials. That proves the path can run; whether the ClamAV
          service itself is alive is the explicit POST /api/clamd/ping, which
          asks the guest through panel/utils/vm_utility.py.
        """
        try:
            return jsonify(clamd.status())
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({"reachable": False, "ok": False, "checks": [],
                            "error": f"{type(exc).__name__}: {exc}"})

    @app.post("/api/clamd/ping")
    def clamd_ping():
        """Ping the ClamAV Service Through the VM Utility Server
        ---
        tags: [clamav]
        responses:
          200:
            description: >-
              `ok` says the utility server answered; `alive` is the service's
              own verdict. `response` is the utility server's reply verbatim.
        description: >
          Opens the VM utility socket with panel/utils/socket_validator.py and
          calls VirtualUtility.ping_service(Service.CLAMD_SERVICE) in
          panel/utils/vm_utility.py. This asks the guest whether clamav is
          running; it sends no clamd command and opens no SSH session.
        """
        try:
            return jsonify(clamd.ping())
        except Exception as exc:  # noqa: BLE001 - a status probe must not 500
            return jsonify({"ok": False, "alive": False, "detail": str(exc),
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

    @app.get("/api/clamd/results/<path:name>")
    def clamd_result_document(name):
        """One Scan Result Document, as Written
        ---
        tags: [clamav]
        parameters:
          - in: path
            name: name
            required: true
            type: string
            description: A bare result file name ending in .json, as listed by /api/clamd/results
        responses:
          200:
            description: >
              `name`, `bytes`, `modified` and `raw` - the file's text unchanged.
          400:
            description: Refused with `code: bad-name` when the name is not a bare .json file name
          404:
            description: Refused with `code: not-found` when no such file exists
        description: >
          The evidence behind a verdict. The page shows the document a row was
          read from; this endpoint returns the bytes as written and recomputes
          nothing. Names are validated as bare `.json` file names, so a crafted
          path cannot read outside python/clamd/results/.
        """
        try:
            return jsonify(clamd.result_document(name))
        except clamd.SubmitError as exc:
            status = 404 if exc.code == "not-found" else 400
            return jsonify(exc.as_dict()), status
        except Exception as exc:  # noqa: BLE001 - a viewer must not 500
            return jsonify({"ok": False, "code": "unreadable",
                            "error": f"{type(exc).__name__}: {exc}"}), 500

    @app.get("/api/clamd/submit")
    def clamd_submit_current():
        """The Scan in Progress, or the Last One
        ---
        tags: [clamav]
        responses:
          200:
            description: >
              A job view (kind=clamd) with the output log so far, or null when
              nothing has been submitted since the panel started.
        description: >
          So a reload reattaches to a scan instead of showing an idle button
          while scan_remote.py is still uploading.
        """
        try:
            return jsonify(clamd.current_submit())
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 200

    @app.post("/api/clamd/submit")
    def clamd_submit():
        """Submit a Sample to ClamAV
        ---
        tags: [clamav]
        consumes: [multipart/form-data]
        parameters:
          - in: formData
            name: file
            required: true
            type: file
            description: The sample to scan (25 MiB limit, clamd's StreamMaxLength)
          - in: formData
            name: mode
            required: false
            type: string
            enum: [sftp, tcp]
            description: >
              Optional, and only to be refused when it disagrees. The transport
              is read from config/dynamic_analysis.json, the same setting the
              Dynamic Analysis > Configuration page writes; sending a different
              mode is a 400 (mode-locked) rather than a silent divergence.
        responses:
          202:
            description: Job handle; poll /api/build/<job_id> for the output log
          400:
            description: >
              Refused with a machine-readable `code`: config-error,
              mode-locked, bad-mode, transport-unavailable, bad-name, empty,
              stage-failed
          409:
            description: A scan is already running
          413:
            description: The sample exceeds SUBMIT_MAX_BYTES
        description: >
          The one action with real side effects. The transport is whatever
          config/dynamic_analysis.json selects, so this page cannot check one
          path and scan through another: sftp runs python/clamd/scan_remote.py,
          tcp opens a socket with panel/utils/socket_validator.py and sends
          clamd's INSTREAM command. Every transport writes the same result
          document under python/clamd/results/, so the Results tab cannot tell
          which one produced a row. The scripts in python/clamd/ and the socket
          client in panel/utils/ are used as-is; the panel reimplements neither.
        """
        upload = request.files.get("file")
        if upload is None or not (upload.filename or "").strip():
            return jsonify({"ok": False, "code": "no-file",
                            "error": "send multipart/form-data with a 'file' "
                                     "field naming the sample"}), 400
        mode = (request.form.get("mode") or "").strip().lower() or None
        try:
            result = clamd.start_submit(upload.filename, upload.stream, mode)
        except Exception as exc:  # noqa: BLE001 - report, never 500 silently
            return jsonify({"ok": False,
                            "error": f"{type(exc).__name__}: {exc}"}), 500
        if result.get("ok"):
            return jsonify(result), 202
        if "already" in str(result.get("error")):
            return jsonify(result), 409
        return jsonify(result), 413 if result.get("code") == "too-large" else 400


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

    @app.get("/api/qiling/submit")
    def qiling_submit_info():
        """Qiling Submission Transport and Last Run
        ---
        tags: [qiling]
        responses:
          200:
            description: Selected transport, availability and current/last job
        description: >
          The transport is read from config/dynamic_analysis.json - the same
          choice the Dynamic Analysis page writes. SFTP runs
          admin-terminal/qiling_upload.py; TCP uses panel/utils/vm_utility.py
          through the operator's socket client. The page reads this to decide
          whether the Submit button can run, and to reattach after a reload.
        """
        try:
            return jsonify(qiling.submission_info())
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({"error": f"{type(exc).__name__}: {exc}",
                            "ready": False, "current": None})

    @app.post("/api/qiling/submit")
    def qiling_submit():
        """Submit a Sample to Qiling
        ---
        tags: [qiling]
        consumes: [multipart/form-data]
        parameters:
          - in: formData
            name: file
            required: true
            type: file
            description: Windows PE executable (25 MiB limit)
          - in: formData
            name: timeout
            required: false
            type: integer
            description: Emulation time limit in seconds (1-600, default 60)
          - in: formData
            name: max_insn
            required: false
            type: integer
            description: Instruction limit (1-100000000, default 1000000)
          - in: formData
            name: mode
            required: false
            type: string
            enum: [sftp, tcp]
            description: >
              Optional, and only to be refused when it disagrees. The transport
              is read from config/dynamic_analysis.json; sending a different
              mode is a 400 (mode-locked).
        responses:
          202:
            description: Job handle; poll /api/build/<job_id> for the output log
          400:
            description: >
              Refused with a machine-readable `code`: config-error,
              mode-locked, bad-mode, transport-unavailable, bad-name, empty,
              stage-failed, bad-limit
          409:
            description: A Qiling run is already in progress
          413:
            description: The sample exceeds SUBMIT_MAX_BYTES
        description: >
          Runs the sample on the analysis VM and writes one
          *_qiling_out.zip under qiling_dlls/results/. Both transports use the
          repo's existing tooling as-is; the panel reimplements neither.
        """
        upload = request.files.get("file")
        if upload is None or not (upload.filename or "").strip():
            return jsonify({"ok": False, "code": "no-file",
                            "error": "send multipart/form-data with a 'file' "
                                     "field naming the sample"}), 400
        mode = (request.form.get("mode") or "").strip().lower() or None
        timeout = request.form.get("timeout")
        max_insn = request.form.get("max_insn")
        try:
            result = qiling.start_submit(
                upload.filename, upload.stream, mode,
                timeout if timeout not in (None, "") else None,
                max_insn if max_insn not in (None, "") else None)
        except Exception as exc:  # noqa: BLE001 - report, never 500 silently
            return jsonify({"ok": False,
                            "error": f"{type(exc).__name__}: {exc}"}), 500
        if result.get("ok"):
            return jsonify(result), 202
        if "already" in str(result.get("error")):
            return jsonify(result), 409
        return jsonify(result), 413 if result.get("code") == "too-large" else 400

    @app.post("/api/qiling/ping")
    def qiling_ping():
        """Ping the Qiling Service Through the VM Utility Server
        ---
        tags: [qiling]
        responses:
          200:
            description: >-
              `ok` says the utility server answered; `alive` is the service's
              own verdict. `response` is the utility server's reply verbatim.
        description: >
          Opens the VM utility socket with panel/utils/socket_validator.py and
          calls VirtualUtility.ping_service(Service.QILING_SERVICE) in
          panel/utils/vm_utility.py. This asks the guest whether the Qiling
          service is running; it opens no SSH session.
        """
        try:
            return jsonify(qiling.ping())
        except Exception as exc:  # noqa: BLE001 - a status probe must not 500
            return jsonify({"ok": False, "alive": False, "detail": str(exc),
                            "error": f"{type(exc).__name__}: {exc}"})

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

    # --- endpoint configuration ---------------------------------------------

    @app.get("/api/network/endpoints")
    def endpoint_config():
        """Service Endpoints, Interface Addresses and the Agent Template
        ---
        tags: [network]
        responses:
          200:
            description: Editable and fixed endpoints, local addresses, agent config
        description: >
          Only the Analyzer API is editable (`SA_API_HOST` / `SA_API_PORT` in
          .env). MalAPI and the ML scorer are listed as fixed: analysis runs
          launch their own copies at 127.0.0.1:60000 and :60010 (src/main.cpp),
          so a change to those two would only move the standalone service and
          silently disagree with the next analysis.

          `addresses` is read with ifaddr, so the choices are addresses this
          host actually has. `agent` is the endpoint agent's Kafka
          broker/topic plus a filled agent.json template; the panel cannot push
          it to installed agents.
        """
        return jsonify(endpoints.snapshot())

    @app.put("/api/network/endpoints/<key>")
    def endpoint_apply(key):
        """Change One Service Endpoint, Validate It, and Optionally Restart
        ---
        tags: [network]
        parameters:
          - name: key
            in: path
            required: true
            type: string
            description: analyzer (the only editable endpoint)
          - name: body
            in: body
            required: true
            schema:
              type: object
              properties:
                host: {type: string}
                port: {type: integer}
                restart: {type: boolean}
        responses:
          200:
            description: Saved, unchanged, or saved with a shadowing warning
          400:
            description: Invalid host, invalid port, or port owned by another service
          404:
            description: No editable endpoint under that key
          409:
            description: A running service could not be stopped, so nothing was written
        description: >
          An IP literal must belong to one of this host's interfaces (ifaddr) -
          an address the machine does not currently have would bind in .env and
          fail at start. The port is tested with a real bind(), not a listener
          scan, and the service's own current port is exempt or no change could
          ever be saved.

          With `restart`, the running service is stopped BEFORE .env is
          written, because the stop path finds its listener by the port in
          .env; writing first would leave the old process running on a port the
          panel no longer knows about. A failed stop aborts the save.
        """
        body = request.get_json(silent=True) or {}
        try:
            if "host" not in body or "port" not in body:
                raise endpoints.EndpointError(
                    "host and port are required", "invalid-host", 400)
            result = endpoints.apply(
                key, body["host"], body["port"],
                restart=bool(body.get("restart", True)))
        except endpoints.EndpointError as exc:
            return jsonify(ok=False, error=str(exc), code=exc.code,
                           key=key), exc.status
        return jsonify(result), endpoints.HTTP_STATUS.get(result["code"], 200)

    @app.put("/api/network/agent")
    def agent_config_save():
        """Set the Endpoint Agent's Kafka Broker and Topic
        ---
        tags: [network]
        parameters:
          - name: body
            in: body
            required: true
            schema:
              type: object
              properties:
                brokers: {type: string, description: "host:port, comma separated"}
                topic: {type: string}
        responses:
          200:
            description: Saved, with the validation warnings and the new template
          400:
            description: Malformed broker address or topic
        description: >
          Kafka is the agent's only transport, so there is no transport picker.
          An IP literal must be one of this host's addresses - the broker runs
          here, and an endpoint agent elsewhere can only reach an address the
          host actually has. Reachability is reported as a warning, not a
          refusal: configuring a broker while it is stopped is a normal setup
          step.

          Nothing on this host restarts: these two keys feed the template the
          operator copies beside the agent executable.
        """
        body = request.get_json(silent=True) or {}
        if "brokers" not in body or "topic" not in body:
            return jsonify(ok=False, code="invalid-brokers",
                           error="brokers and topic are required"), 400
        result = endpoints.save_agent(body["brokers"], body["topic"])
        return jsonify(result), 400 if not result["ok"] else 200

    return app


# Defined at module scope, not inside create_app(): create_app returns `app`
# here, so anything placed after it would be unreachable dead code nested in
# this function rather than a helper the route above can call.
#
# Every YAML fact below comes out of PyYAML - through python/panel/core/yamlview.py,
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
