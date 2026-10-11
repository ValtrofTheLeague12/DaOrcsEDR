#!/usr/bin/env bash
# qilin-check-service.sh - pre-flight checks for the qilin systemd service
# run as the qilin user on the VM; exits 1 if any check fails
set -u

FAILURES=0

echo "[*] Checking APT package manager"
if command -v apt >/dev/null 2>&1; then
    echo "[+] apt found: $(command -v apt)"
else
    echo "[-] apt not found"
    FAILURES=$((FAILURES + 1))
fi

echo "[*] Checking python3"
if command -v python3 >/dev/null 2>&1; then
    echo "[+] python3 found: $(python3 --version 2>&1)"
else
    echo "[-] python3 not installed"
    FAILURES=$((FAILURES + 1))
fi

echo "[*] Checking qilin-service.service"
if command -v systemctl >/dev/null 2>&1; then
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
    export XDG_RUNTIME_DIR
    state="$(systemctl --user is-active qilin-service.service 2>/dev/null)"
    if [ "${state}" = "active" ]; then
        echo "[+] qilin-service.service is active"
        systemctl --user status qilin-service.service --no-pager -n 5 2>/dev/null
    elif [ "${1:-}" = "--pre-flight" ]; then
        echo "[!] qilin-service.service not active yet (state: ${state:-unknown}) - expected before first deploy"
    else
        echo "[-] qilin-service.service is not active (state: ${state:-unknown})"
        FAILURES=$((FAILURES + 1))
    fi
else
    echo "[-] systemctl not found"
    FAILURES=$((FAILURES + 1))
fi

if [ "${FAILURES}" -gt 0 ]; then
    echo "[-] ${FAILURES} check(s) failed"
    exit 1
fi
echo "[+] all checks passed"
exit 0
