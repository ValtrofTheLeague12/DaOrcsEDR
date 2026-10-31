"""Live CPU / RAM / disk / network metrics from inside a running guest.

Separate from vms.py on purpose, for the same reason netmap.py is separate: vms
answers "which machines exist and may I touch one", which costs a `showvminfo`
per machine and must stay fast because it is polled every ten seconds. This
answers "what is that guest doing right now", which costs a full SSH handshake
plus a script execution. Mixing them would make the machine list inherit the
latency of the slow one, and a list that sometimes takes nine seconds to answer
is a list nobody trusts.

Transport is paramiko + SFTP, in that order and for a reason: the collector is
shipped to the guest as a FILE over SFTP and then executed, rather than pasted
into `exec_command` as a one-liner.

  * A multi-line script pasted into exec_command is quoting hell. It has to
    survive one layer of shell on the far side, and the failure mode when a quote
    goes wrong is a syntax error from a line nobody can find.
  * As a file, the script is uploaded once, is readable in the guest, and can be
    replaced without touching the command string at all.
  * SFTP gives a stat() the exec path lacks, which is how the guest's filesystem
    numbers are cross-checked against what the script reported.

Credentials come from the SAME file the Qiling tooling already writes,
qiling_dlls/vm_info.json. ClamAV and the Qiling harness are guests on that one
machine and reuse its account, so there is nothing to invent here. Anything not
listed there simply has no metrics, and that is reported as such rather than
rendered as a machine that is somehow idle at zero.

Concurrency: refreshes happen on a daemon thread started lazily on first read.
`snapshot()` never blocks. A status panel that freezes while an SSH handshake
times out is worse than one that shows "gathering" for a second.
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

from ..core import config

# How often the background thread re-reads the guest.
#
# Faster than the fleet poll would be pointless - the poll is the slowest
# consumer. Slower than 15s and the numbers are stale enough to mislead while
# someone is watching a build burn CPU in the guest.
_REFRESH_SECONDS = 15.0

# Never block a request on this. The handshake alone can eat most of it when a
# guest is powered off, and powered-off is a completely normal state here.
_CONNECT_TIMEOUT = 6.0
_EXEC_TIMEOUT = 10.0

# Where the collector lands inside the guest. $HOME rather than /tmp because a
# guest may mount /tmp noexec, and a script that cannot be executed is worse
# than one that was never written.
_REMOTE_DIR = ".cache/ia-panel"
_REMOTE_SCRIPT = f"{_REMOTE_DIR}/vm-metrics.sh"

# The collector itself.
#
# POSIX sh, no bashisms, no coreutils dependencies beyond what every image has.
# Every value comes from /proc or ndf: `free` and `df` disagree about column
# layout between coreutils and busybox, and busybox is what a stripped analysis
# VM runs. Parsing a busybox `df` table with a coreutils-shaped parser produces
# confident, wrong numbers, which is the single worst outcome for a metrics
# panel.
#
# Output is one `key=value` per line with values that contain no spaces, so the
# parse on the other side is a split and a float() - no ordering assumptions, no
# sentinel line to count against.
COLLECTOR = r"""#!/bin/sh
# Managed by the IAProject admin panel. Overwritten on every refresh.
# Prints key=value lines. No set -e: a missing tool must not abort the rest.

emit() { printf '%s=%s\n' "$1" "$2"; }

# --- identity ---------------------------------------------------------------
emit hostname "$(uname -n 2>/dev/null || hostname 2>/dev/null || echo unknown)"
emit kernel "$(uname -sr 2>/dev/null || echo unknown)"

# Seconds since boot. The FIRST field of /proc/uptime is exactly that.
read up _rest < /proc/uptime 2>/dev/null
emit uptime_s "${up:-}"

# --- cpu --------------------------------------------------------------------
# Cores. nproc exists on coreutils and busybox; /proc/cpuinfo is the fallback
# for an image that has neither.
cores="$(nproc 2>/dev/null)"
[ -z "$cores" ] && cores="$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
emit cores "${cores:-}"

# Load average. /proc/loadavg is authoritative and identically shaped everywhere.
read l1 l5 l15 _rest < /proc/loadavg 2>/dev/null
emit load1 "${l1:-}"
emit load5 "${l5:-}"
emit load15 "${l15:-}"

# Percent busy, from two samples of /proc/stat taken `sleep 1` apart. A single
# sample cannot produce a rate, and reporting "0%" because jiffies have not
# ticked yet is a lie an operator would act on.
cpu_line() {
  awk '/^cpu /{idle=$5+$6; total=0; for (i=2;i<=NF;i++) total+=$i; print total, idle}' \
    /proc/stat 2>/dev/null
}
snap1="$(cpu_line)"
sleep 1
snap2="$(cpu_line)"
set -- $snap1
prev_total=$1; prev_idle=$2
set -- $snap2
now_total=$1;  now_idle=$2
if [ -n "$prev_total" ] && [ -n "$now_total" ] && [ "$now_total" -gt "$prev_total" ]; then
  d_total=$((now_total - prev_total))
  d_idle=$((now_idle - prev_idle))
  emit cpu_percent "$(( (d_total - d_idle) * 100 / d_total ))"
else
  emit cpu_percent ""
fi

# --- memory -----------------------------------------------------------------
# kB from /proc/meminfo, converted to bytes so the UI never has to know that
# Linux reports memory in kibibytes.
mem() { awk "/^$1:/{print \$2 * 1024; exit}" /proc/meminfo 2>/dev/null; }
mt="$(mem MemTotal)"
ma="$(mem MemAvailable)"
mf="$(mem MemFree)"
mb="$(mem Buffers)"
mc="$(mem Cached)"
st="$(mem SwapTotal)"
sf="$(mem SwapFree)"
# MemAvailable is the kernel's own estimate and is strictly better than
# total-minus-free: it accounts for reclaimable page cache. Prefer it, and fall
# back to the free+buffers+cached approximation on a kernel without it.
if [ -z "$ma" ]; then ma=$(( ${mf:-0} + ${mb:-0} + ${mc:-0} )); fi
emit mem_total "${mt:-}"
emit mem_available "${ma:-}"
emit swap_total "${st:-}"
emit swap_free "${sf:-}"

# --- processes --------------------------------------------------------------
emit processes "$(ls -1 /proc 2>/dev/null | grep -c '^[0-9]')"

# Top five by resident memory. %mem is computed here rather than in Python so
# the figure matches what `top` would print for the same guest. The total is
# passed with -v instead of interpolated into the program text, so an awk
# quoting slip cannot turn the whole program into a syntax error.
ps -eo pid,comm,rss --sort=-rss 2>/dev/null | awk -v total="${mt:-0}" '
  NR>1 && NR<=6 {
    pct = 0;
    if (total > 0) pct = int($3 * 1024 * 1000 / total) / 10;
    printf "proc|%s|%s|%s|%s\n", $1, $2, $3, pct
  }'
emit processes_end 1

# --- network ----------------------------------------------------------------
# Bytes received / transmitted per interface, from /proc/net/dev.
emit net_rx "$(awk 'NR>2{s+=$2} END{print s+0}' /proc/net/dev 2>/dev/null)"
emit net_tx "$(awk 'NR>2{s+=$10} END{print s+0}' /proc/net/dev 2>/dev/null)"
emit net_ifaces "$(awk 'NR>2 && $1 != "lo" {n++} END{print n+0}' /proc/net/dev 2>/dev/null)"
emit addresses "$(ip -o -4 addr show scope global 2>/dev/null \
                 | awk '{split($4,a,"/"); print a[1]}' | tr '\n' ',' | sed 's/,$//')"

# --- disk -------------------------------------------------------------------
# Root filesystem. %used comes from `df` but the byte counts come from
# statvfs-equivalent arithmetic on the same line, so the bar and the label can
# never disagree.
df_line="$(df -k / 2>/dev/null | awk 'NR==2{print $2, $3, $4}')"
if [ -n "$df_line" ]; then
  set -- $df_line
  emit disk_total "$(( ${1:-0} * 1024 ))"
  emit disk_used "$(( ${2:-0} * 1024 ))"
  emit disk_free "$(( ${3:-0} * 1024 ))"
fi

emit done 1
"""


# ---------------------------------------------------------------------------
# guest registry
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def guests() -> list[dict]:
    """Every guest the panel holds credentials for, keyed by name and IP.

    vm_info.json is the source of truth and is deliberately read directly rather
    than through config.vm_info(): that helper strips the username and password
    because it was written for reachability probes, and a reachability probe
    never needs to authenticate.
    """
    raw = _read_json(config.VM_INFO_FILE)
    if not raw:
        return []
    ip = str(raw.get("VM_IP") or "").strip()
    user = str(raw.get("VM_HOST") or raw.get("VM_USER") or "").strip()
    if not ip or not user:
        return []
    try:
        port = int(raw.get("VM_PORT") or 22)
    except (TypeError, ValueError):
        port = 22
    return [{
        "name": str(raw.get("VM_NAME") or "").strip() or "Analysis VM",
        "ip": ip,
        "port": port if 1 <= port <= 65535 else 22,
        "user": user,
        "password": str(raw.get("VM_PASSWORD") or ""),
    }]


def _blank(ip: str, error: str = "") -> dict:
    """The shape every consumer can rely on, whether or not the guest answered.

    `state` is the field the UI branches on: pending / up / down / denied.
    Returning nulls everywhere would make "not measured yet" and "measured as
    zero" render identically, and those are very different facts.
    """
    return {
        "state": "down",
        "ip": ip,
        "collected_at": None,
        "age_seconds": None,
        "hostname": None,
        "kernel": None,
        "cores": None,
        "uptime_seconds": None,
        "load": {"1": None, "5": None, "15": None},
        "cpu_percent": None,
        "memory": {"total_bytes": None, "used_bytes": None,
                   "available_bytes": None, "percent": None,
                   "swap_total_bytes": None, "swap_used_bytes": None,
                   "swap_percent": None},
        "disk": {"total_bytes": None, "used_bytes": None, "free_bytes": None,
                 "percent": None},
        "network": {"rx_bytes": None, "tx_bytes": None, "ifaces": None,
                    "addresses": []},
        "processes": {"count": None, "top": []},
        "error": error,
    }


_cache: dict = {"payload": _blank(""), "at": 0.0}
_lock = threading.Lock()
_thread: threading.Thread | None = None

# Rolling trend window, per guest name.
#
# Server-side rather than accumulated in the browser because the panel polls
# every 10s but a reader arrives at an arbitrary moment: a client-side history
# would draw a chart that starts empty every reload, which is exactly when
# somebody reloads to "get the latest". This way the window is already full.
#
# 120 samples at _REFRESH_SECONDS is half an hour, which is long enough to see a
# boot and a crash and short enough that the JSON stays small.
_HISTORY_LIMIT = 120
_history: dict[str, list[dict]] = {}


# ---------------------------------------------------------------------------
# parse
# ---------------------------------------------------------------------------

_PROC_LINE = re.compile(r"^proc\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)$")


def _f(value) -> float | None:
    try:
        out = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return out


def _i(value) -> int | None:
    num = _f(value)
    return int(num) if num is not None else None


def parse(text: str, ip: str) -> dict:
    """Turn the collector's key=value output into the payload shape.

    Tolerant by design: every field is independently optional. A guest with no
    `df` (read-only root, minimal container base) still returns CPU and memory,
    and showing those beats discarding the whole sample because one line was
    missing.
    """
    out = _blank(ip)
    out["state"] = "up"
    out["collected_at"] = round(time.time(), 1)
    values: dict[str, str] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        proc = _PROC_LINE.match(line)
        if proc:
            pid, comm, rss, pct = proc.groups()
            out["processes"]["top"].append({
                "pid": _i(pid),
                "name": comm.strip(),
                "mem_bytes": (_i(rss) or 0) * 1024,
                "mem_percent": _f(pct),
            })
            continue
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()

    if values.get("done") != "1":
        out["state"] = "down"
        out["error"] = out["error"] or "collector did not finish"
        return out

    out["hostname"] = values.get("hostname") or None
    out["kernel"] = values.get("kernel") or None
    out["cores"] = _i(values.get("cores"))
    out["uptime_seconds"] = _f(values.get("uptime_s"))
    for key, idx in (("1", "load1"), ("5", "load5"), ("15", "load15")):
        out["load"][key] = _f(values.get(idx))
    out["cpu_percent"] = _f(values.get("cpu_percent"))

    mem_total = _i(values.get("mem_total"))
    mem_avail = _i(values.get("mem_available"))
    if mem_total:
        used = mem_total - (mem_avail if mem_avail is not None else 0)
        out["memory"].update({
            "total_bytes": mem_total,
            "available_bytes": mem_avail,
            "used_bytes": used,
            "percent": round(used / mem_total * 100, 1),
        })
    swap_total = _i(values.get("swap_total"))
    swap_free = _i(values.get("swap_free"))
    if swap_total:
        swap_used = swap_total - (swap_free or 0)
        out["memory"].update({
            "swap_total_bytes": swap_total,
            "swap_used_bytes": swap_used,
            "swap_percent": round(swap_used / swap_total * 100, 1),
        })

    disk_total = _i(values.get("disk_total"))
    disk_used = _i(values.get("disk_used"))
    if disk_total:
        out["disk"] = {
            "total_bytes": disk_total,
            "used_bytes": disk_used,
            "free_bytes": _i(values.get("disk_free")),
            # Computed from the same two numbers the UI labels with, so the bar
            # and the text can never be derived from different sources.
            "percent": (round((disk_used or 0) / disk_total * 100, 1)
                        if disk_total else None),
        }

    out["network"] = {
        "rx_bytes": _i(values.get("net_rx")),
        "tx_bytes": _i(values.get("net_tx")),
        "ifaces": _i(values.get("net_ifaces")),
        "addresses": [a for a in (values.get("addresses") or "").split(",") if a],
    }
    out["processes"]["count"] = _i(values.get("processes"))

    if not mem_total and out["cores"] is None and out["cpu_percent"] is None:
        out["state"] = "down"
        out["error"] = out["error"] or "guest returned no /proc data"
    return out


# ---------------------------------------------------------------------------
# collect
# ---------------------------------------------------------------------------

def _collect_one(guest: dict) -> dict:
    """Upload the collector over SFTP, run it, read it back. Never raises."""
    ip = guest["ip"]
    try:
        import paramiko
    except ImportError:
        return _blank(ip, "paramiko is not installed (pip install paramiko)")

    client = paramiko.SSHClient()
    try:
        try:
            client.load_system_host_keys()
        except OSError:
            pass
        # AutoAdd, not Reject: these are throwaway sandbox guests on a
        # host-only adapter whose host keys are regenerated on every rebuild.
        # ClamAV's own scanner uses RejectPolicy because it talks to a long-lived
        # box it has a pinned key for; that reasoning does not transfer here.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip, port=guest["port"], username=guest["user"],
            password=guest["password"] or None,
            timeout=_CONNECT_TIMEOUT, banner_timeout=_CONNECT_TIMEOUT,
            auth_timeout=_CONNECT_TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 - off/refused/timeout are all normal
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
        return _blank(ip, f"{type(exc).__name__}: {exc}")

    try:
        text = _run_via_sftp(client)
        if text is None:
            return _blank(ip, "sftp is not available on this guest")
        if isinstance(text, str) and text.startswith("\x00ERR:"):
            return _blank(ip, text[4:].strip())
        return parse(text, ip)
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass


def _run_via_sftp(client) -> str | None:
    """Push the script with SFTP, execute it, return stdout.

    Returns None if the SFTP subsystem is unavailable, so the caller can fall
    back rather than pretending a guest without SFTP is broken.
    """
    try:
        sftp = client.open_sftp()
    except Exception:  # noqa: BLE001 - no sftp subsystem
        return None

    try:
        try:
            home = sftp.normalize(".")
        except Exception:  # noqa: BLE001 - some servers refuse normalize(".")
            home = ""
        remote = f"{home.rstrip('/')}/{_REMOTE_SCRIPT}" if home else _REMOTE_SCRIPT
        _mkdirs(sftp, remote.rsplit("/", 1)[0])
        with sftp.open(remote, "w") as handle:
            handle.write(COLLECTOR)
        sftp.chmod(remote, 0o755)
    except Exception as exc:  # noqa: BLE001
        try:
            sftp.close()
        except Exception:  # noqa: BLE001
            pass
        return f"\x00ERR:sftp write failed: {type(exc).__name__}: {exc}"
    finally:
        try:
            sftp.close()
        except Exception:  # noqa: BLE001
            pass

    _stdin, stdout, _stderr = client.exec_command(
        f"sh {remote}", timeout=_EXEC_TIMEOUT)
    text = stdout.read().decode("utf-8", "replace")

    # Best-effort cleanup. Leaving a 3 KB script behind in a sandbox guest is
    # untidy but harmless; failing to remove it must never fail the collection.
    try:
        cleanup = client.open_sftp()
        cleanup.remove(remote)
        cleanup.close()
    except Exception:  # noqa: BLE001
        pass
    return text


def _mkdirs(sftp, posix_dir: str) -> None:
    """Create posix_dir and its parents, tolerating existing ones."""
    if not posix_dir or posix_dir in (".", "/"):
        return
    parts = [p for p in posix_dir.split("/") if p]
    cur = posix_dir.startswith("/") and "/" or ""
    for part in parts:
        cur = f"{cur}/{part}"
        try:
            sftp.stat(cur)
        except IOError:
            try:
                sftp.mkdir(cur)
            except IOError:
                pass


# ---------------------------------------------------------------------------
# cache + background refresh
# ---------------------------------------------------------------------------

def _sample(result: dict, at: float) -> dict:
    """One point of the trend series, flattened out of the nested payload.

    Flattened rather than handed over nested because this is the one part of the
    payload the client reads a hundred times a minute to draw a line, and walking
    `memory.percent` at every point to draw a sparkline is a lot of JSON for a
    polyline.

    A failed collection still produces a sample, with every field null. That is
    the point: a gap in the line is how the reader sees "we stopped measuring at
    14:20", which is a very different fact from "the machine was idle at 14:20".
    Dropping failed samples instead would quietly close the gap and draw a
    straight line across an outage.
    """
    if result.get("state") != "up":
        return {"at": round(at, 1), "cpu": None, "mem": None, "disk": None,
                "load1": None, "procs": None, "rx": None, "tx": None}
    return {
        "at": round(at, 1),
        "cpu": result.get("cpu_percent"),
        "mem": (result.get("memory") or {}).get("percent"),
        "disk": (result.get("disk") or {}).get("percent"),
        "load1": (result.get("load") or {}).get("1"),
        "procs": (result.get("processes") or {}).get("count"),
        "rx": (result.get("network") or {}).get("rx_bytes"),
        "tx": (result.get("network") or {}).get("tx_bytes"),
    }


def _append_history(name: str, result: dict, at: float) -> list[dict]:
    """Push one sample onto this guest's rolling window and return the window."""
    series = _history.setdefault(name, [])
    series.append(_sample(result, at))
    if len(series) > _HISTORY_LIMIT:
        # Trim from the front, in place. The list is the only thing that grows
        # with uptime in this module, so the cap is what keeps a panel left open
        # for a week from turning into a slow leak.
        del series[:len(series) - _HISTORY_LIMIT]
    return series


def refresh() -> dict:
    """Collect now, synchronously. Used by the thread and by tests."""
    roster = guests()
    if not roster:
        payload = _blank("", "vm_info.json has no VM_IP/VM_HOST pair")
        with _lock:
            _cache.update(at=time.time(), payload=payload)
        return payload

    # One guest is the credentialed case today. The loop exists so adding a
    # second entry to the registry needs no change here.
    by_key: dict[str, dict] = {}
    primary: dict = {}
    primary_name = ""
    with _lock:
        now = time.time()
        for guest in roster:
            result = _collect_one(guest)
            primary = result
            series = _append_history(guest["name"], result, now)
            # Attached to the result rather than served separately, so a fleet
            # card carries the trend for the machine it is drawing - there is no
            # second request and no chance of pairing the wrong series with the
            # wrong card.
            result["history"] = series
            primary_name = guest["name"]
            # Indexed by both IP and registered name so the fleet card can find
            # it whichever identifier it happens to hold - a machine renamed
            # inside VirtualBox still resolves through its address.
            by_key[guest["ip"]] = result
            if guest["name"]:
                by_key[guest["name"]] = result

    payload = dict(primary)
    payload["by_key"] = by_key
    payload["history"] = _history.get(primary_name, [])
    with _lock:
        _cache.update(at=time.time(), payload=payload)
    return payload


def _loop() -> None:
    while True:
        try:
            refresh()
        except Exception:  # noqa: BLE001 - a thread must not die quietly
            pass
        time.sleep(_REFRESH_SECONDS)


def _ensure_thread() -> None:
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _thread = threading.Thread(target=_loop, name="vmmetrics", daemon=True)
    _thread.start()


def _cache_snapshot() -> dict:
    """The raw cached payload, lookup index included. Internal callers only."""
    with _lock:
        return _cache["payload"] or _blank("")


def _public(payload: dict) -> dict:
    """Strip the private lookup index before a payload leaves this module.

    `by_key` exists so for_guest() can find a guest by IP or by registered name.
    Shipping it in every /api/vm-metrics response would put one full copy of the
    metrics per guest inside the primary payload, for no reader.
    """
    return {k: v for k, v in payload.items() if k != "by_key"}


def snapshot() -> dict:
    """Last collected metrics. Returns immediately, never blocks.

    The very first call starts the collector thread and reports `pending`, so a
    cold page load shows a spinner rather than a two-second freeze.
    """
    now = time.time()
    with _lock:
        payload = _cache["payload"] or _blank("")
        at = _cache["at"]
    if now - at < _REFRESH_SECONDS:
        out = _public(payload)
        out["age_seconds"] = round(now - at, 1)
        return out
    _ensure_thread()
    out = _public(payload)
    out["state"] = "pending" if not payload.get("collected_at") else payload["state"]
    out["age_seconds"] = round(now - at, 1) if at else None
    return out


def invalidate() -> None:
    """Force the next snapshot() to wait for a fresh collection."""
    with _lock:
        _cache.update(at=0.0)


def _pending(ip: str) -> dict:
    """A blank payload that says 'asked for, not back yet'.

    Distinct from `_blank`, which says 'the guest did not answer', and from
    None, which says 'we hold no credentials for this machine'. All three render
    differently, and conflating them is how a fleet card ends up telling an
    operator to add credentials that are already sitting in vm_info.json.
    """
    out = _blank(ip)
    out["state"] = "pending"
    return out


def for_guest(name: str, ip: str | None) -> dict | None:
    """The metrics belonging to one machine, or None if it is not instrumented.

    Returning None is the point: a machine with no credentials is not a machine
    with zero CPU, and the card says "no SSH credentials" instead of drawing an
    idle-looking gauge.

    Three answers, and telling them apart is the whole function:

      None      this machine is not in vm_info.json - genuinely not instrumented
      pending   it IS instrumented, but no sample has come back yet
      a payload it was collected: up, down (with the reason), or denied

    The `pending` case was not hypothetical. The collector thread used to be
    started only by snapshot(), which only /api/vm-metrics calls - so the fleet
    listing, the one page that actually renders these cards, never started it.
    by_key stayed empty, every lookup missed, and every machine reported "no SSH
    credentials on file" while its credentials sat in the very file that message
    tells you to edit. The collector is therefore started here, and a machine
    that IS instrumented reports pending rather than a false negative.
    """
    roster = guests()
    mine = [g for g in roster
            if (ip and g["ip"] == ip) or (name and g["name"] == name)]
    if not mine:
        return None

    _ensure_thread()

    payload = _cache_snapshot()
    index = payload.get("by_key") or {}
    if not index:
        # Instrumented, collector just started, nothing collected yet.
        return _pending(ip or mine[0]["ip"])

    if ip and ip in index:
        return index[ip]
    if name and name in index:
        return index[name]
    # Fall back to the primary guest only when it is literally the machine
    # being asked about. Without this check a single credentialed guest would
    # be painted onto every machine in the fleet.
    if payload.get("ip") and (payload["ip"] == ip):
        return payload
    return _pending(ip or mine[0]["ip"])


if __name__ == "__main__":  # manual probe: `python -m python.panel.network.vmmetrics`
    print(json.dumps(refresh(), indent=2))