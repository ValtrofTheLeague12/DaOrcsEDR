"""Configuration for the admin orchestration panel.

One place that decides where everything lives, so no other module has to
rediscover the repo layout or re-implement `.env` precedence.

Port resolution deliberately mirrors the rest of the project - process env,
then the repository `.env`, then a loopback default - because the code
defaults are NOT what is actually running. `server.py` defaults to 60020 but
`.env` sets `SA_API_PORT=60025`. Hardcoding either number produces a panel that
reports every service as down.

The panel itself refuses to be reachable from off-box. `bind_host()` widens
nothing: this is a local operator console that proxies to services which are
themselves loopback-bound, and there is no scenario where binding 0.0.0.0 helps.
That is a deliberate difference from admin-terminal's `core.bind_addr()`, which
widens because the C++ analyzer dials 127.0.0.1 - a constraint the panel does
not have.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ENV_FILE = REPO / ".env"
ADMIN_TERMINAL = REPO / "admin-terminal"
COMPOSE_FILE = REPO / "compose.yaml"
KAFKA_COMPOSE_FILE = REPO / "kafka-agent" / "docker-compose.yaml"

# Everything the project GENERATES lives under one AppData root, named after the
# application basename rather than after any one component. This mirrors
# include/core/app_paths.hpp on the C++ side - the two must agree, because the
# panel tails the analyzer's logs and neither should have to care which language
# wrote them.
#
#     %APPDATA%/IAProject/logs          run logs, crash reports, trace.txt
#     %APPDATA%/IAProject/cache         provider and tool caches
#     %APPDATA%/IAProject/panel-cache   this panel's own cache
#     %APPDATA%/IAProject/bundle-keys   evidence-bundle encryption keys
#     %APPDATA%/IAProject/mega-secrets  sealed MEGA credentials
#
# exports/ and data/ deliberately stay in the tree: results are what an operator
# browses and hands to someone else, and the corpus is checked in.
APP_NAME = "IAProject"


def appdata_root() -> Path:
    """The one directory every generated file belongs under.

    IA_APPDATA_DIR overrides it, which is what the tests use to get a throwaway
    tree instead of writing into the real profile.
    """
    override = os.environ.get("IA_APPDATA_DIR")
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        if base:
            return Path(base) / APP_NAME
        return Path.home() / "AppData" / "Roaming" / APP_NAME
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / APP_NAME
    return Path.home() / ".local" / "share" / APP_NAME


def logs_dir() -> Path:
    """Where the analyzer writes logs, dumps, trace and resume checkpoints."""
    return appdata_root() / "logs"


def cache_dir() -> Path:
    """Regenerable provider/tool caches."""
    return appdata_root() / "cache"


def panel_cache_dir() -> Path:
    """This panel's own cache. Not machine state the analyzer knows about."""
    return appdata_root() / "panel-cache"


PANEL_HOST = "127.0.0.1"
PANEL_PORT_DEFAULT = 60100

# Probe timeouts, and they are short on purpose.
#
# This used to be a single 20s value for every service. A closed loopback port
# answers with RST rather than dropping, so those fail in milliseconds and never
# needed it - but an unreachable address (the analysis VM when it is powered off)
# burns the FULL timeout waiting for nothing. Ten services probed concurrently
# meant one dead VM held the whole Services page for 20 seconds, and because
# /api/overview, /api/stats and /api/docs each ran their own pass, that was paid
# three times over on a cold load.
#
# Loopback gets a tight budget; a routable address gets a longer one because a
# host that is genuinely booting will take seconds to answer its first connect,
# and calling that "down" would be a lie.
PANEL_TIMEOUT = 2.5
PANEL_TIMEOUT_REMOTE = 6.0

VBOXMANAGE = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")

# Upload staging. ml/serve.py's /score takes a FILESYSTEM PATH, so the panel
# has to own a directory it can pass without ever forwarding a client-supplied
# path to a service that will parse whatever it is given.
UPLOAD_DIR = REPO / "exports" / "_panel_uploads"
UPLOAD_MAX_BYTES = 256 * 1024 * 1024

# What the panel's sample box may be pointed at. The roots are relative to
# REPO; an absolute path is accepted only when it resolves inside one of them,
# and the name must end in an allowed executable extension. Shared by the run
# gate (pipeline_run.start) and the picker's inspect endpoint, via
# python/panel/samples.py, so the two can never refuse different things.
SAMPLE_ROOTS = ("samples", "tests/fixtures", "exports")
ALLOWED_SAMPLE_EXT = {".exe", ".dll", ".bin", ".sys"}

# Operator uploads are staged here, scanned, then moved into samples/.
# Relative to REPO and resolved at call time for the same reason SAMPLE_ROOTS
# are relative: a caller that points REPO elsewhere (a test, a relocated repo)
# must not stage into the real exports/.
SAMPLE_UPLOAD_DIR = "exports/_panel_uploads"

# The upload cap, deliberately small. The factory's own bait is kilobytes; the
# picker needs a file the analyzer can open whole; and an executable this
# project did not build is exactly the thing to keep small enough to eyeball.
# Enforced WHILE streaming - an over-size body is cut off mid-write, never
# buffered whole and then measured.
SAMPLE_UPLOAD_MAX_BYTES = 1024 * 1024


def setting(name: str, default: str = "") -> str:
    """Process env, then .env, then default. Same precedence as server.py."""
    if name in os.environ:
        return os.environ[name]
    try:
        raw = ENV_FILE.read_text(encoding="utf-8-sig")
    except OSError:
        return default
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Split on the first `=` and compare the whole key, rather than matching
        # a `name=` prefix.
        #
        # The prefix form was quietly wrong in two ways: it ignored any spaces a
        # human wrote around the `=` - so `SA_API_PORT = 60025` fell through to
        # the default with nothing to say so - and it could satisfy a request for
        # SA_API_PORT from a line reading SA_API_PORT_EXTRA=...
        key, sep, value = stripped.partition("=")
        if not sep or key.strip() != name:
            continue
        return value.strip().strip("\"'")
    return default


def setting_int(name: str, default: int) -> int:
    try:
        return int(setting(name, str(default)))
    except ValueError:
        return default


def _loopback(host: str) -> bool:
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def analyzer_base() -> str:
    """The analyzer REST API.

    probe_host() mirrors core.py: a service reached over the LAN still has to be
    dialled on loopback, because the analyzer binds every interface.
    """
    host = setting("SA_API_HOST", "127.0.0.1")
    return f"{'127.0.0.1' if not _loopback(host) else host}:{analyzer_port()}"


def analyzer_port() -> int:
    return setting_int("SA_API_PORT", 60020)


def malapi_base() -> str:
    host = setting("MALAPI_HOST", "127.0.0.1")
    return f"{'127.0.0.1' if not _loopback(host) else host}:{malapi_port()}"


def malapi_port() -> int:
    return setting_int("MALAPI_PORT", 60000)


def ml_base() -> str:
    host = setting("ML_HOST", "127.0.0.1")
    return f"{'127.0.0.1' if not _loopback(host) else host}:{ml_port()}"


def ml_port() -> int:
    return setting_int("ML_PORT", 60010)


def ml_token() -> str:
    return setting("ML_SERVE_TOKEN", "")


def cyberchef_port() -> int:
    # Hardcoded in admin-terminal/core.py, not .env. Mirrored rather than
    # invented so the panel and the TUI agree on what "CyberChef" means.
    return 60001


def cyberchef_ui_port() -> int:
    return 8081


def guacamole_port() -> int:
    return 61000


def kafka_port() -> int:
    return 9092


def kafka_ui_port() -> int:
    return 8080


def panel_port() -> int:
    return setting_int("ADMIN_WEB_PORT", PANEL_PORT_DEFAULT)


# Written by the Qiling setup tooling; python/qiling/_check_vm_connection.py
# reads the same file. Read directly rather than importing that module: it is
# private, it lives outside this package, and importing it would drag the whole
# qiling checker in just to read three keys out of a JSON file.
VM_INFO_FILE = REPO / "qiling_dlls" / "vm_info.json"


def vm_info() -> dict:
    """VM_NAME / VM_IP / PORT for the analysis VM, or {} if not configured.

    Deliberately forgiving: a missing or half-written vm_info.json means "the VM
    is not set up yet", not "the panel is broken", so every failure returns an
    empty dict and the caller skips the service rather than reporting it down.
    """
    import json

    try:
        data = json.loads(VM_INFO_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    ip = str(data.get("VM_IP") or "").strip()
    if not ip:
        return {}
    try:
        port = int(data.get("VM_PORT", data.get("PORT", 22)))
    except (TypeError, ValueError):
        port = 22
    return {
        "name": str(data.get("VM_NAME") or "").strip() or "Analysis VM",
        "ip": ip,
        "port": port if 1 <= port <= 65535 else 22,
    }


def bind_host() -> str:
    """Always loopback.

    Kept as a function rather than a constant so the intent is obvious at the
    call site and so there is exactly one thing to change if that ever stops
    being true. There is deliberately no widening here.
    """
    return PANEL_HOST


def compose_projects() -> list[dict]:
    """The two compose files in this repo, with the service allowlist.

    Parsed from disk so the panel never accepts a container name from a
    request: anything not listed here cannot be started or stopped through
    this API even if someone crafts the URL.
    """
    out = []
    for label, path in (("ia", COMPOSE_FILE), ("kafka-agent", KAFKA_COMPOSE_FILE)):
        if not path.is_file():
            continue
        out.append({"label": label, "file": path, "services": _compose_services(path)})
    return out


_VOLUMES = {"volumes", "networks", "services", "configs", "secrets"}


def _compose_services(path: Path) -> list[str]:
    """Service names under `services:` - two-space indent, no deeper."""
    names: list[str] = []
    in_services = False
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return names
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            in_services = line.strip() == "services:"
            continue
        if not in_services:
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 2 and line.rstrip().endswith(":"):
            name = line.strip().rstrip(":").strip()
            if name and name not in _VOLUMES:
                names.append(name)
    return names


def service_allowed(project: str, service: str) -> bool:
    for proj in compose_projects():
        if proj["label"] == project:
            return service in proj["services"]
    return False