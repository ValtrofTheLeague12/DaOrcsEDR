#!/usr/bin/env bash
# In-VM clamd connection test. Executed by the host (_configure_clamd.py,
# paramiko) which exports the endpoint from vm_info.json as env vars; it can
# also be run by hand inside the VM. Defaults match a Debian/Kali clamd.
#
#   CLAMD_MODE=unix|tcp  CLAMD_SOCKET=...  CLAMD_HOST=...  CLAMD_PORT=...
#   CLAMD_CONF=...       CLAMD_DB_DIR=...
#
# Exit: 0 every required check passed, 1 at least one failed.
set -u

MODE="${CLAMD_MODE:-unix}"
SOCKET="${CLAMD_SOCKET:-/var/run/clamav/clamd.ctl}"
HOST="${CLAMD_HOST:-127.0.0.1}"
PORT="${CLAMD_PORT:-3310}"
CONF="${CLAMD_CONF:-/etc/clamav/clamd.conf}"
DB_DIR="${CLAMD_DB_DIR:-/var/lib/clamav}"

pass=0
fail=0

ok()  { printf '[+] OK    %s\n' "$1"; pass=$((pass + 1)); }
ko()  { printf '[-] FAIL  %s\n' "$1"; fail=$((fail + 1)); }
note(){ printf '[*] %s\n' "$1"; }

note "clamd connection test (mode=$MODE)"

# 1. clamdscan client
if command -v clamdscan >/dev/null 2>&1; then
    ok "clamdscan present ($(command -v clamdscan))"
else
    ko "clamdscan not found in PATH (install clamav-client)"
fi

# 2. daemon process
clamd_pid="$(pgrep -x clamd 2>/dev/null | head -1 || true)"
if [ -n "$clamd_pid" ]; then
    ok "clamd process running (pid $clamd_pid)"
elif pgrep -f 'clamd@' >/dev/null 2>&1; then
    ok "clamd@ instance running (pid $(pgrep -f 'clamd@' | head -1))"
else
    ko "no clamd process found"
fi

# 3. endpoint reachable
case "$MODE" in
    unix)
        if [ -S "$SOCKET" ]; then
            ok "control socket exists: $SOCKET"
        elif [ -e "$SOCKET" ]; then
            ko "$SOCKET exists but is not a socket"
        else
            ko "control socket missing: $SOCKET"
        fi
        ;;
    tcp)
        if timeout 3 bash -c "exec 3<>/dev/tcp/${HOST}/${PORT}" 2>/dev/null; then
            ok "tcp endpoint open: ${HOST}:${PORT}"
        else
            ko "tcp endpoint unreachable: ${HOST}:${PORT}"
        fi
        ;;
    *)
        ko "unknown CLAMD_MODE '$MODE' (use unix or tcp)"
        ;;
esac

# 4. protocol PONG (clamdscan --ping first, raw PING fallback)
conf_args=""
if [ -n "$CONF" ] && [ -f "$CONF" ]; then
    conf_args="-c $CONF"
fi
pong_ok=0
if command -v clamdscan >/dev/null 2>&1; then
    if pong_out="$(clamdscan $conf_args --ping 30 2>&1)"; then
        ok "PING -> PONG (clamdscan --ping)"
        pong_ok=1
    else
        note "clamdscan --ping failed: $(echo "$pong_out" | head -1)"
    fi
fi
if [ "$pong_ok" -eq 0 ]; then
    if command -v nc >/dev/null 2>&1; then
        if [ "$MODE" = "unix" ]; then
            raw="$(printf 'PING\n' | timeout 5 nc -U "$SOCKET" 2>/dev/null || true)"
        else
            raw="$(printf 'PING\n' | timeout 5 nc "$HOST" "$PORT" 2>/dev/null || true)"
        fi
        case "$raw" in
            *PONG*) ok "PING -> PONG (raw protocol)"; pong_ok=1 ;;
            *)      ko "no PONG from clamd" ;;
        esac
    elif [ "$MODE" = "tcp" ]; then
        raw="$(timeout 5 bash -c \
            "exec 3<>/dev/tcp/${HOST}/${PORT} && printf 'PING\n' >&3 && head -1 <&3" \
            2>/dev/null || true)"
        case "$raw" in
            *PONG*) ok "PING -> PONG (raw protocol)"; pong_ok=1 ;;
            *)      ko "no PONG from clamd" ;;
        esac
    else
        ko "cannot verify PONG (install netcat or clamdscan)"
    fi
fi

# 5. daemon version (proves it answers VERSION, not just accepts sockets)
if command -v clamdscan >/dev/null 2>&1; then
    if ver="$(clamdscan $conf_args --version 2>&1 | head -1)" && \
           echo "$ver" | grep -qi clam; then
        ok "version: $ver"
    else
        note "clamdscan --version: $(echo "$ver" | head -1)"
    fi
fi

# 6. signature database freshness (informational, never fails the test)
newest="$(find "$DB_DIR" -maxdepth 1 \( -name '*.cvd' -o -name '*.cld' \) \
    -printf '%T@\n' 2>/dev/null | sort -n | tail -1)"
if [ -n "$newest" ]; then
    age_days=$(( ( $(date +%s) - ${newest%.*} ) / 86400 ))
    if [ "$age_days" -gt 7 ]; then
        note "signature DBs are ${age_days} day(s) old - run freshclam"
    else
        ok "signature DBs fresh (${age_days} day(s) old)"
    fi
else
    note "no signature DBs found in $DB_DIR"
fi

if [ "$fail" -eq 0 ]; then
    printf '[+] clamd connection OK (%d checks passed)\n' "$pass"
    exit 0
fi
printf '[-] clamd connection FAILED (%d check(s) failed)\n' "$fail"
exit 1
