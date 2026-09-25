# tudor-moc libfprint TOD driver

An out-of-tree [libfprint TOD](https://gitlab.freedesktop.org/libfprint/libfprint) driver
for the Synaptics **Match-on-Chip** (Augusta) fingerprint sensors `06cb:00bc` (Dell
Latitude 7210 2-in-1) and `06cb:00a9`.

Unlike the old in-tree `tudor.c` (an `FpImageDevice` that captured + matched on the host),
this is an **`FpDevice`** driver: the sensor enrolls/verifies **on-chip** and never returns
a raw image. It implements `probe/open/close/enroll/verify/identify/list/delete/
clear-storage/cancel/suspend/resume` by embedding CPython and driving the reverse-engineered
`pydrv` (`tudor.sensor.SensorMatcher` / `SensorDB2`) over the already-established TLS 1.2
channel. See `../pydrv/tudor/sensor/moc.py`, `db2.py` and `../docs/frame-capture-re.md`.

## How it works
- `src/pyembed.c` embeds one CPython interpreter (no sub-interpreters — extension-safe),
  compiles a small wrapper module, and exposes typed C calls (`pyembed_open`,
  `pyembed_capture_frame`, `pyembed_enroll_*`, `pyembed_identify`, `pyembed_list_templates`,
  `pyembed_delete_template`). The wrapper resolves the pairing data path itself via
  `tudor.paths.resolve_pdata(sensor.id.hex())`.
- `src/device.c` is the `FpDevice`. Blocking pydrv work runs on a per-operation worker
  `GThread`; progress / finger-status / completion are marshalled back to fprintd's main
  context with `g_idle`, so every `fpi_device_*` call happens on the main thread. Cancel is
  cooperative (a wrapper flag polled by the pydrv capture loop).
- **FpPrint mapping:** `fpi-data = (y @ay @ay) = (finger, tuid[16], user_id)`. The 16-byte
  on-chip TUID (from the final enroll `add_image`) is authoritative; verify/identify resolve
  the matched TUID back to a stored `FpPrint`. Enroll commits under a host-synthesized
  WINBIO SID derived from fprintd's `user_id` (via `make_linux_sid`). There is **no
  host-side template encryption**; the sensor's DB2 store is authoritative.

## Prerequisites (Arch)
```sh
yay -S libfprint-tod fprintd        # TOD-enabled libfprint (replaces stock libfprint) + fprintd
# pydrv must be importable by the embedded interpreter (see pydrv_path below).
```
The sensor must already be paired (pairing data at `<state-dir>/<id>.pdata`, resolved by
`tudor.paths`: `$TUDOR_STATE_DIR` / `$XDG_CONFIG_HOME/tudor` / `/etc/tudor`). fprintd runs
as root and uses `/etc/tudor`.

## Build & install
```sh
# pydrv_path bakes the default sys.path entry for the `tudor` package into the module.
# Default (empty) uses ../pydrv relative to this source tree; set it explicitly for a
# system install.
meson setup build -Dpydrv_path=/home/dylan/repos/synaTudor/pydrv
ninja -C build
sudo ninja -C build install     # installs the .so into tod_driversdir + the udev rule
sudo udevadm control --reload && sudo udevadm trigger --subsystem-match=usb
```
Runtime override (no rebuild): `TUDOR_PYDRV_PATH=/path/to/pydrv`.

## Validate
```sh
# fprintd sees the device:
fprintd-list "$USER" ; # or: dbus / fprintd-enroll picks it up
fprintd-enroll          # press finger ~8 times until 100%
fprintd-verify          # matching finger -> match; other finger -> no-match
fprintd-delete "$USER"
```
PAM: enable `pam_fprintd` for `sudo`/login and test.

## Files
| file | purpose |
|---|---|
| `src/tudor-moc.h` | device struct, constants |
| `src/pyembed.{c,h}` | embedded CPython + wrapper + typed C API |
| `src/device.c` | `FpDevice` class + vfuncs + worker/main marshalling |
| `60-tudor-moc.rules` | udev: `uaccess` + driver tag for `06cb:00bc`/`00a9` |
| `meson.build`, `meson_options.txt` | build |

## Known limitations / follow-ups
- `list` returns TUID-only prints (the on-chip template payload isn't host-readable), which
  is expected for MOC; fprintd's own per-user DB carries labels.
- `suspend`/`resume` are no-ops; if a real system suspend resets the sensor, recovery is via
  libfprint close/reopen (untested across suspend yet).
- Score threshold is `TUDOR_MOC_SCORE_THRESHOLD` (default 0 = trust the firmware's
  match/no-match decision).
