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

from flask import Flask, jsonify, make_response, request

from . import (artifacts, auth, clamd, config, containers, docs, logs,
               netmap, qiling, services, stats, system, vms)

try:
    from flasgger import Swagger
except ImportError:  # pragma: no cover - optional; the panel still runs without it
    Swagger = None

# Endpoints that must stay reachable without a session, or the UI can never log
# itself in.
_PUBLIC = {"/api/health", "/api/auth/state", "/api/auth/login"}


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)

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

          Read-only. Uploading stays a CLI action (`python mega/upload.py
          --artifact <name>`): it pushes analysis evidence to cloud storage, and
          that is not something a polled status page should be able to trigger.

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

    # --- virtual machines ----------------------------------------------------

    @app.get("/api/vms")
    def list_vms():
        """Registered VirtualBox Machines With IP and Live Services
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
        """
        try:
            return jsonify(vms.listing())
        except Exception as exc:  # noqa: BLE001 - a status page must not 500
            return jsonify({"generated_at": None, "vms": [], "available": False,
                            "counts": {"total": 0, "running": 0},
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
        """
        if action not in ("start", "stop"):
            return jsonify(ok=False, error="action must be start or stop"), 400
        body = request.get_json(silent=True) or {}
        result = vms.control(str(body.get("name") or ""), action)
        code = 200 if result["ok"] else 502
        return jsonify(result), code

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