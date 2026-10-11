#!/usr/bin/env bash
# qilin-service installer - runs ON the VM as the target user, after
# _configure_quiling.py has uploaded the payload:
#   qilin-service.service  -> <unit_dir>/   (via sftp)
#   qilin-script.py        -> <app_dir>/    (via sftp)
#   rootfs.tar.gz          -> <app_dir>/    (via sftp)
# usage:
#   bash qilin-service.install.sh <app_dir> <unit_dir>
set -euo pipefail

APP_DIR="${1:?usage: qilin-service.install.sh <app_dir> <unit_dir>}"
UNIT_DIR="${2:?usage: qilin-service.install.sh <app_dir> <unit_dir>}"

mkdir -p "$APP_DIR" "$UNIT_DIR"

if [ -f "$APP_DIR/rootfs.tar.gz" ]; then
    echo "[*] extracting rootfs.tar.gz ..."
    tar -xzf "$APP_DIR/rootfs.tar.gz" -C "$APP_DIR"
    rm -f "$APP_DIR/rootfs.tar.gz"
    echo "[+] rootfs -> $APP_DIR/rootfs (tar deleted)"
else
    echo "[*] rootfs.tar.gz not present - skipping extraction"
fi

XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export XDG_RUNTIME_DIR
if systemctl --user daemon-reload; then
    echo "[+] daemon-reload ok"
else
    echo "[!] daemon-reload failed - unit file is installed anyway" >&2
fi

echo "[+] install finished"
