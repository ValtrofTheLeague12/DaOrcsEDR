"""Health of every service in the stack, read from their REAL endpoints.

Nothing here reimplements a service's idea of "am I up". Each probe asks the
service itself - GET /health where it publishes one, a TCP connect where it
does not. That is the whole point of the panel being an orchestrator: if the
analyzer is healthy, the analyzer says so.

Where a service has no health endpoint at all (Kafka is a broker, not an HTTP
service) the panel falls back to a port connect and SAYS that is what it did,
rather than dressing a TCP connect up as an application-level check.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import NamedTuple

from ..core import config
from ..network import netinfo


@dataclass
class Spec:
    """What a service IS, as opposed to whether it is answering right now.

    Separated from the probe result on purpose: the facts here are static
    configuration (where it lives, what it is for) and stay correct while the
    service is down, which is exactly when an operator most wants to read them.
    Keeping them out of the probe means a dead endpoint still explains itself.
    """

    key: str
    name: str
    description: str
    host: str
    port: int
    scheme: str = "http"
    kind: str = "http"          # 'http' probe or 'tcp' connect
    health_path: str = "/health"
    role: str = "core"          # groups the cards on the panel
    ui_path: str | None = None  # a page a human can actually open, when one exists
    auth: bool = False          # needs a token to probe
    routes: tuple[str, ...] = ()  # extra GET paths probed alongside /health
    optional: bool = False      # omit the card entirely if not configured

    @property
    def base(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def endpoint(self) -> str:
        """The exact URL that gets probed - what to paste into curl."""
        if self.kind == "tcp":
            return self.base
        return self.base + self.health_path


def _specs() -> list[Spec]:
    """Every service the panel watches, resolved from config.

    Built fresh per call rather than module-level, because config reads .env -
    and editing .env is exactly the moment somebody wants to re-probe and see
    the new port, not a value frozen at import time.
    """
    return [
        Spec(
            key="analyzer", name="Analyzer API", role="analysis",
            description="REST wrapper around the static analyzer. Accepts a "
                        "sample upload, runs it through a named pipeline and "
                        "returns the artifacts.",
            host=config.analyzer_base().rsplit(":", 1)[0],
            port=config.analyzer_port(),
            # A green /health only proves Flask is up. These are the routes an
            # analysis actually depends on, so each is fetched separately: a
            # 404 on /capabilities is a different fault from a dead service and
            # the card should be able to say so.
            routes=("/phases", "/pipelines", "/capabilities", "/tasks"),
        ),
        Spec(
            key="malapi", name="MalAPI", role="analysis",
            description="Classification of imported Windows API calls by how "
                        "malicious they are. Enriches the import table.",
            host=config.malapi_base().rsplit(":", 1)[0],
            port=config.malapi_port(),
        ),
        Spec(
            key="ml", name="ML scorer", role="analysis",
            description="LightGBM EMBER2024 model server. Scores a PE file and "
                        "returns a malicious-family probability.",
            host=config.ml_base().rsplit(":", 1)[0],
            port=config.ml_port(),
            auth=bool(config.ml_token()),
        ),
        Spec(
            key="kafka", name="Kafka broker", role="pipeline",
            description="Message bus feeding the kafka-agent pipeline. A broker, "
                        "not an HTTP service, so this is a port connect.",
            host="127.0.0.1", port=config.kafka_port(),
            scheme="tcp", kind="tcp",
        ),
        Spec(
            key="cyberchef", name="CyberChef API", role="pipeline",
            description="Headless CyberChef for decoding and transforming the "
                        "strings, hex and encoded blobs the analyzer finds.",
            host="127.0.0.1", port=config.cyberchef_port(),
        ),
        # --- the browser UIs --------------------------------------------
        # These were configured in config.py and exposed by both compose files
        # but never probed, so the panel could report every API green while a
        # user staring at a blank page at :8081 had no idea why.
        Spec(
            key="cyberchef-ui", name="CyberChef UI", role="pipeline",
            description="The CyberChef web interface - the human-facing side of "
                        "the decoder, for working a payload by hand.",
            host="127.0.0.1", port=config.cyberchef_ui_port(),
            health_path="/", ui_path="/",
        ),
        Spec(
            key="kafka-ui", name="Kafka UI", role="pipeline",
            description="Topic browser for the analysis-artifacts stream. The "
                        "only place to see what the agent has actually sent.",
            host="127.0.0.1", port=config.kafka_ui_port(),
            health_path="/", ui_path="/",
        ),
        Spec(
            key="guacamole", name="Guacamole", role="access",
            description="Browser-based RDP/VNC/SSH client - the way into the "
                        "analysis VM's desktop without leaving the console.",
            host="127.0.0.1", port=config.guacamole_port(),
            health_path="/", ui_path="/",
        ),
        # --- the panel itself -------------------------------------------
        Spec(
            key="panel", name="Admin panel", role="core",
            description="This console, and the Flask API it is served from. "
                        "If it is down nothing else on the page can update.",
            host="127.0.0.1", port=config.panel_port(),
            health_path="/api/health",
            routes=("/api/config", "/api/system", "/api/containers"),
        ),
        # --- the analysis VM --------------------------------------------
        # Skipped rather than shown as down when vm_info.json is absent: an
        # unconfigured VM is a setup state, not an outage, and listing it red
        # every poll would be crying wolf.
        _vm_spec(),
    ]


def _vm_spec() -> Spec:
    """The analysis VM's Spec, or an unconfigured placeholder when there is no
    vm_info.json yet."""
    info = config.vm_info()
    if not info:
        return Spec(
            key="qiling-vm", name="Analysis VM", role="access",
            description="The Qiling analysis VM. Not configured - no "
                        "qiling_dlls/vm_info.json, so there is no address to "
                        "probe yet.",
            host="", port=0, scheme="tcp", kind="tcp", optional=True,
        )
    return Spec(
        key="qiling-vm",
        name=str(info["name"]),
        role="access",
        description="The Qiling analysis VM. Hosts the emulation harness and "
                    "the clamd scanner; reached over SSH from here.",
        host=info["ip"], port=info["port"], scheme="tcp", kind="tcp",
    )


# ---------------------------------------------------------------------------
# Endpoint lookup, for surfaces that know a container but not a Spec.
#
# The Containers panel reads docker and never touches a Spec, so it cannot call
# spec.endpoint - but a card that cannot say where to open a service is a card
# that sends the reader to the compose file. This is the join between the two
# worlds: docker says "I published 127.0.0.1:60001->3000", the Spec says "the
# CyberChef API answers on http://127.0.0.1:60001/health", and the card needs
# the second fact.
#
# The host port is the join key because it is the one thing that cannot drift:
# it is what docker actually bound. A name match would be reading .env and
# hoping it still describes reality.
# ---------------------------------------------------------------------------

class EndpointIndex(NamedTuple):
    """Lookup tables for `resolve()`, built once per snapshot by the caller."""

    by_port: dict[int, dict]
    by_name: dict[str, dict]


def endpoint_index() -> EndpointIndex:
    """Every watched service's entrypoint, indexed by host port and by name.

    Built fresh per call for the same reason as _specs(): config reads .env, and
    the moment someone edits a port is the moment they want the next card to
    show it. The caller builds this once per snapshot rather than per container,
    because config has no cache of its own and a ten-card page would otherwise
    re-read .env twenty times for one render.
    """
    by_port: dict[int, dict] = {}
    by_name: dict[str, dict] = {}
    for spec in _specs():
        if spec.optional and not spec.host:
            # Not configured. Listed as "not set up" by services.py already, and
            # it has no address to hand a container card, so it is not indexed.
            continue
        record = {
            "key": spec.key,
            "service": spec.name,
            "url": spec.endpoint,
            "kind": spec.kind,
            "ui_url": (spec.base + spec.ui_path) if spec.ui_path else None,
        }
        # First spec wins a contested port: two services bound to the same port
        # is a misconfiguration, and picking the earlier one at least keeps the
        # page deterministic between polls.
        by_port.setdefault(spec.port, record)
        by_name.setdefault(spec.key, record)
        if spec.name != spec.key:
            by_name.setdefault(spec.name.lower().replace(" ", "-"), record)
    return EndpointIndex(by_port=by_port, by_name=by_name)


def resolve(index: EndpointIndex, *, ports=(), service: str | None = None) -> dict | None:
    """The entrypoint record for a container, or None when nothing matches.

    Two lookups, in this order:

    1. a published HOST port - what docker bound, so it cannot be stale.
    2. the compose service name - which is how a container that does not exist
       yet ("Not created", no ports row) still gets its endpoint, and how a
       service published only to another interface is still recognised. This
       one can drift with .env, which is exactly why it is second.

    A container the panel has no Spec for - a one-off `podman run`, an image
    nobody wrote a Spec for - returns None rather than a guess.
    """
    for port in sorted({int(p) for p in ports or () if p}):
        hit = index.by_port.get(port)
        if hit:
            return hit
    if service:
        return index.by_name.get(service)
    return None


# Latency trend per service. Same shape of idea as system.py's ring buffer:
# in-process, reset on panel restart, no persistence - a status page that
# quietly writes a database is a status page that eventually needs migrating.
HISTORY_LEN = 60
MIN_SAMPLE_INTERVAL = 2.0
_history: dict[str, deque] = {}
_last_sample: float = 0.0


def _record(probes: list[Probe]) -> None:
    """Append one latency sample per probe, per overview() call."""
    global _last_sample
    now = time.time()
    if now - _last_sample < MIN_SAMPLE_INTERVAL:
        return
    _last_sample = now
    for p in probes:
        track = _history.setdefault(p.key, deque(maxlen=HISTORY_LEN))
        # Null when down, so the sparkline breaks the line rather than drawing a
        # confident zero for a service that refused the connection.
        track.append(p.ms if p.up else None)


def _trend(key: str) -> dict:
    """Latency samples for one service. Nulls where it was down."""
    track = list(_history.get(key, ()))
    return {"samples": len(track), "ms": track}


@dataclass
class Probe:
    key: str
    name: str
    endpoint: str
    up: bool = False
    code: str = ""
    note: str = ""
    ms: float = 0.0
    kind: str = "http"
    detail: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _get(url: str, timeout: float, headers: dict | None = None) -> tuple[int, bytes, str]:
    """GET a URL. Returns (status, body, error). Never raises."""
    req = urllib.request.Request(url, method="GET")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(65536), ""
    except urllib.error.HTTPError as exc:
        # An HTTP error still proves something is listening and speaking HTTP.
        try:
            body = exc.read(65536)
        except Exception:  # noqa: BLE001
            body = b""
        return exc.code, body, ""
    except urllib.error.URLError as exc:
        return 0, b"", str(getattr(exc, "reason", exc))
    except Exception as exc:  # noqa: BLE001 - a probe must never kill the panel
        return 0, b"", f"{type(exc).__name__}: {exc}"


def _json_of(body: bytes) -> dict:
    try:
        parsed = json.loads(body.decode("utf-8", "replace"))
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, UnicodeDecodeError):
        return {}


def _http_probe(key: str, name: str, url: str, timeout: float,
                headers: dict | None = None,
                expect_auth: bool = False) -> Probe:
    p = Probe(key=key, name=name, endpoint=url)
    started = time.perf_counter()
    code, body, err = _get(url, timeout, headers)
    p.ms = round((time.perf_counter() - started) * 1000, 1)
    p.code = str(code) if code else "down"

    # 401/403 means two very different things depending on who was supposed to
    # be holding a token. For a service the panel authenticates to (expect_auth),
    # it is a real fault - our token is missing or wrong. For a browser UI the
    # human logs into, it is simply the service working correctly, and calling
    # it "down" would report an outage where there is none.
    challenged = code in (401, 403)
    if challenged and not expect_auth:
        p.up = True
        p.code = "auth"
        p.note = "Listening, but requires sign-in (HTTP %d)" % code
        return p

    p.up = 200 <= code < 400
    if err and not p.up:
        p.note = err
        return p
    payload = _json_of(body)
    if p.up and payload:
        # Surface whatever the service says about itself rather than guessing.
        for field_name in ("status", "version", "model", "trees", "features"):
            if field_name in payload:
                p.detail[field_name] = payload[field_name]
        if not p.note:
            status = payload.get("status")
            p.note = f"status={status}" if status else f"HTTP {code}"
    elif p.up:
        p.note = f"HTTP {code}"
    return p


def _tcp_probe(key: str, name: str, host: str, port: int, timeout: float) -> Probe:
    p = Probe(key=key, name=name, endpoint=f"tcp://{host}:{port}", kind="tcp")
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            p.up = True
            p.code = "connected"
            p.note = "TCP connect ok (no health endpoint published)"
    except OSError as exc:
        p.code = "down"
        p.note = f"{type(exc).__name__}: {exc}"
    p.ms = round((time.perf_counter() - started) * 1000, 1)
    return p


def _probe_routes(spec: Spec, timeout: float, headers: dict | None) -> dict[str, int]:
    """GET each extra route, returning {path: status}.

    Skipped entirely for a service that is already down - there is no point
    opening four more connections to a host that just refused us, and a down
    service's routes would only ever report the same connection error.
    """
    if not spec.routes or spec.kind != "http":
        return {}

    def fetch(path: str) -> tuple[str, int]:
        code, _body, _err = _get(spec.base + path, timeout, headers)
        return path, code

    with ThreadPoolExecutor(max_workers=len(spec.routes)) as pool:
        return dict(pool.map(fetch, spec.routes))


def _timeout_for(host: str) -> float:
    """Loopback fails fast; a routable address is allowed to take its time."""
    return config.PANEL_TIMEOUT if _loopback(host) else config.PANEL_TIMEOUT_REMOTE


def _loopback(host: str) -> bool:
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _probe_spec(spec: Spec, headers: dict | None = None) -> Probe:
    timeout = _timeout_for(spec.host)
    if spec.kind == "tcp":
        return _tcp_probe(spec.key, spec.name, spec.host, spec.port, timeout)
    p = _http_probe(spec.key, spec.name, spec.endpoint, timeout, headers,
                    expect_auth=spec.auth)
    if p.up:
        routes = _probe_routes(spec, timeout, headers)
        if routes:
            p.detail["routes"] = routes
    return p


def probe_all(timeout: float | None = None) -> list[Probe]:
    """Probe every service concurrently - sequential probes would serialise
    ten connection timeouts into a multi-second page load.

    `timeout` is normally None, in which case each probe gets its budget from
    _timeout_for() based on whether its host is loopback or routable.
    """
    ml_token = config.ml_token()
    ml_headers = {"Authorization": f"Bearer {ml_token}"} if ml_token else {}

    # Optional specs that are not configured are dropped here rather than
    # probed as down: an absent vm_info.json means "not set up", and a red card
    # for it on every poll would train the eye to ignore red cards.
    specs = [s for s in _specs() if not s.optional or s.host]
    if not specs:
        return []

    with ThreadPoolExecutor(max_workers=max(1, len(specs))) as pool:
        futures = {
            pool.submit(_probe_spec, spec, ml_headers if spec.auth else None): spec
            for spec in specs
        }
        results = []
        for fut, spec in futures.items():
            try:
                results.append(fut.result())
            except Exception as exc:  # noqa: BLE001 - one bad probe must not
                # take down the page; report it as down with the reason.
                results.append(
                    Probe(key=spec.key, name=spec.name, endpoint=spec.endpoint,
                          kind=spec.kind, code="down",
                          note=f"{type(exc).__name__}: {exc}")
                )
    # Preserve the declared order rather than completion order.
    order = {spec.key: i for i, spec in enumerate(specs)}
    results.sort(key=lambda p: order.get(p.key, 0))
    return results


# Probe cache.
#
# /api/overview, /api/stats and /api/docs all need the same probe results, and
# each of them used to run its own full pass - so opening the console cold fired
# three identical rounds of connection attempts in parallel, and the slowest one
# (a powered-off VM timing out) set the load time for all three pages. Caching the
# whole payload means the second and third caller get it for free.
#
# 4s matches containers.py's snapshot cache, so both surfaces stay coherent.
_OVERVIEW_CACHE_TTL = 5.0
_overview_cache: dict = {"at": 0.0, "payload": None}


def _build_overview() -> dict:
    specs = [s for s in _specs() if not s.optional or s.host]
    probes = probe_all()
    _record(probes)
    return {
        "services": [
            {
                **p.as_dict(),
                # Static facts merged onto each result, so the card can render
                # description / host / port / role without a second lookup.
                "description": spec.description,
                "host": spec.host,
                "port": spec.port,
                "scheme": spec.scheme,
                "role": spec.role,
                "ui_url": (spec.base + spec.ui_path) if spec.ui_path else None,
                "auth": spec.auth,
                "trend": _trend(p.key),
                # Routing facts for the address this service answers on, so the
                # Services cards can show interface/CIDR/class without the UI
                # having to fetch a second endpoint. Computed here rather than
                # imported from docs.py because docs already imports this module.
                "net": netinfo.network_facts(spec.host, spec.port),
            }
            for p, spec in zip(probes, specs)
        ],
        "up": sum(1 for p in probes if p.up),
        "total": len(probes),
        "roles": sorted({s.role for s in specs}),
        "endpoints": {s.key: s.endpoint for s in specs},
        "ml_auth": bool(config.ml_token()),
    }


def overview() -> dict:
    """The Services panel payload: probes plus the resolved endpoints.

    Cached for _OVERVIEW_CACHE_TTL. Endpoints come back too, because "why is it
    pointing there" is the first question when something is red, and the answer
    lives in .env.
    """
    now = time.time()
    if _overview_cache["payload"] is not None and \
            now - _overview_cache["at"] < _OVERVIEW_CACHE_TTL:
        return _overview_cache["payload"]
    payload = _build_overview()
    # Stamped AFTER the build, not before. The probe pass itself takes several
    # seconds, so recording the pre-probe time would write an entry that is
    # already expired by the time it lands - and every caller would re-probe,
    # which is the exact thing the cache exists to prevent.
    _overview_cache.update(at=time.time(), payload=payload)
    return payload