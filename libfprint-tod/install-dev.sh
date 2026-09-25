#!/usr/bin/env bash
# Dev install for the tudor-moc TOD driver. Must run as root (writes under /usr/lib and
# restarts fprintd). Stages the pydrv `tudor` package to a system path because fprintd.service
# runs with ProtectHome=true (it cannot read the repo under /home).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
PYDRV_DST=/usr/lib/tudor-moc/pydrv                 # must match -Dpydrv_path / baked default
TOD_DIR="$(pkg-config --variable=tod_driversdir libfprint-2-tod-1)"

if [[ $EUID -ne 0 ]]; then echo "run as root (sudo bash $0)"; exit 1; fi

echo "[*] Staging pydrv 'tudor' package -> $PYDRV_DST/tudor"
install -d "$PYDRV_DST"
rm -rf "$PYDRV_DST/tudor"
cp -r "$REPO/pydrv/tudor" "$PYDRV_DST/tudor"
find "$PYDRV_DST" -type d -name __pycache__ -prune -exec rm -rf {} +

echo "[*] Installing module -> $TOD_DIR/libtudor_moc_tod.so"
install -Dm755 "$HERE/build/libtudor_moc_tod.so" "$TOD_DIR/libtudor_moc_tod.so"

echo "[*] Ensuring udev rule is present"
install -Dm644 "$HERE/60-tudor-moc.rules" /etc/udev/rules.d/60-tudor-moc.rules
udevadm control --reload
udevadm trigger --subsystem-match=usb

echo "[*] Restarting fprintd (dbus-activated; stop is enough to force reload next use)"
systemctl restart fprintd 2>/dev/null || systemctl stop fprintd 2>/dev/null || true

echo "[*] Done:"
ls -l "$TOD_DIR/" "$PYDRV_DST/"
