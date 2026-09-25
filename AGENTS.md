# Agent onboarding

Fork of `Popax21/synaTudor` bringing the Synaptics `06cb:00bc` fingerprint sensor
(Dell Latitude 7210 2-in-1, "Augusta", fw 10.1) up on Linux. It is a **match-on-chip
(MOC)** sensor: enroll/verify happen on the device and no raw image is pulled to the host.

This file is the stable onboarding reference: environment, build/test, structure, and
permissions. **It intentionally contains no status/history.**

## Where status & history live (read these first)
- [`docs/00bc-porting.md`](docs/00bc-porting.md) — source of truth: prior art, branch
  layout, phased strategy, and the dated **running log**. Append to it as you work.
- [`docs/frame-capture-re.md`](docs/frame-capture-re.md) — detailed, independently
  validated binary RE of the capture/MOC protocol.
- [`docs/00bc-roadmap.md`](docs/00bc-roadmap.md) — **outstanding work**, each item scoped
  as a standalone session. Pick one per session; update it + the running log as you go.

## Environment
- **Target host:** the Arch Linux tablet with the physical (internal) sensor. Sessions run
  either directly on the tablet as user `dylan` (in `wheel`; `sudo` needs a password) or
  over SSH as host `tablet` (root, key-only). The human at the tablet performs finger
  presses for enroll/verify tests.
- **Python:** system `python3` (3.14) with `pyusb` + `cryptography`. `pydrv/` is pure
  Python; run it via the system interpreter (it self-inserts its dir on `sys.path`, or set
  `PYTHONPATH=pydrv`).
- **Toolchain (all present via pacman):** `base-devel` (gcc/make/binutils/pkgconf), `meson`,
  `ninja`, `glib2`, `libgusb`, `json-glib`, `nss`, `openssl`, `pixman`, plus the Python
  embed headers (`python3-embed` pkg-config).
- **libfprint/fprintd:** the TOD-enabled libfprint from the AUR (`libfprint-tod`,
  1.95.2+tod1 — provides `libfprint-2-tod-1.pc` and `tod_driversdir=/usr/lib/libfprint-2/tod-1`;
  it *replaces* stock `libfprint`) plus `fprintd` from `extra`. Install with
  `yay -S libfprint-tod fprintd`.

## Project structure & key files
- `pydrv/` — the reverse-engineered Python driver (owns the sensor: pairing, TLS 1.2,
  command channel, MOC).
  - `tudor/comm.py` — `Command` opcodes, `USBCommunication`, `CommandFailedException`.
  - `tudor/paths.py` — state-dir resolver (`$TUDOR_STATE_DIR` → `$XDG_CONFIG_HOME/tudor`
    → `/etc/tudor`) for pairing data + host stores.
  - `tudor/sensor/{sensor,pair,event,iota,bootloader}.py` — session/init/events.
  - `tudor/sensor/moc.py` — `SensorMatcher` (`enroll_loop`/`capture_one_frame`/
    `enroll_commit`/`verify`/`identify`, `CaptureCancelled`).
  - `tudor/sensor/db2.py` — `SensorDB2` (per-user template enumeration, `delete_template`).
  - `tudor/driver/drvcmd/{enroll,verify,templates,tmpl_store}.py` — REPL commands + host
    label↔TUID store.
  - `tudor/sensor/{sensor_keys/,builtin_fw/}` — bundled keys/firmware (secrets; don't print).
  - `diag/*.py` — read-only/on-device probes (`verify_probe`, `enroll_probe`,
    `db2_list_probe`, `probe_getversion`, …).
- `libfprint-tod/` — the shipping **`FpDevice` MOC TOD driver** (embeds CPython, drives
  pydrv). `src/{device.c,pyembed.c/h,tudor-moc.h}`, `meson.build`, `60-tudor-moc.rules`,
  `install-dev.sh`, `tools/moc_selftest.c`, and `README.md` + `PAM.md`.
- `libfprint/` — vendored upstream libfprint **1.90.7** tree (reference only: `goodixmoc/`
  and the old `FpImageDevice` `tudor.c`). Not the build target.
- `wincapture/` — Frida kit used to capture Windows ground-truth enroll/verify.
- `rev/` — binary-RE reference material (adapter/USB DLL dumps + IOCTL notes).
- `docs/` — see "Where status & history live".

## Build, install, run
- **pydrv probes** (no build): `python3 -u pydrv/diag/<probe>.py`. Most read-only probes
  need only the sensor; enroll/verify need finger presses.
- **Driver build:**
  ```sh
  meson setup libfprint-tod/build -Dpydrv_path=/usr/lib/tudor-moc/pydrv   # once
  ninja -C libfprint-tod/build
  ```
  (`pydrv_path` bakes the default `sys.path` entry for `tudor`; override at runtime with
  `$TUDOR_PYDRV_PATH`.)
- **Install (root):** `sudo bash libfprint-tod/install-dev.sh` — stages `pydrv/tudor` to
  `/usr/lib/tudor-moc/pydrv` (fprintd runs `ProtectHome`, so it can't read `/home`),
  installs `libtudor_moc_tod.so` to `tod_driversdir`, ensures the udev rule, and restarts
  fprintd. The module basename **must** start with `lib` (the TOD loader only scans `lib*.so`).

## Testing
- **Isolated (no fprintd, no sudo)** — the self-test harness runs the driver in a plain C
  process (Python only inside the module, like fprintd):
  ```sh
  gcc libfprint-tod/tools/moc_selftest.c -o /tmp/moc_selftest \
      $(pkg-config --cflags --libs libfprint-2)
  FP_TOD_DRIVERS_DIR=libfprint-tod/build TUDOR_PYDRV_PATH=pydrv \
      /tmp/moc_selftest <list|enroll|verify|identify|identify-loop|delete-all>
  ```
- **Via fprintd:** `fprintd-enroll`, `fprintd-verify`, `fprintd-list`, `fprintd-delete`.
- **PAM:** see `libfprint-tod/PAM.md` (enable `pam_fprintd` for `sudo` first; it is
  `sufficient`, so it falls back to the password — no lockout risk). Fingerprint prompts
  need a real TTY, so run PAM tests in an interactive terminal, not through tooling.
- **Debug env:** `TUDOR_MOC_DEBUG=1` (driver/pydrv wrapper traces to stderr);
  `G_MESSAGES_DEBUG=all` (libfprint + TOD loader).
- **Finger coordination:** a capture window is a silent ~25–30 s blind wait (tools buffer
  output — the presser gets no live prompt). Agree a "GO", then press+lift firmly/centered
  every ~2 s for the whole window. MOC is probabilistic: a poor press yields a legitimate
  no-match; retry.

## Permissions & access
- **USB (non-root):** the udev rule `libfprint-tod/60-tudor-moc.rules` (`TAG+="uaccess"`
  for `06cb:00bc`/`00a9`) grants the active seat user rw, so pydrv/pyusb works without sudo.
  Install it and `sudo udevadm control --reload && sudo udevadm trigger` (replug if needed).
  fprintd runs as root and has access regardless.
- **State/secrets:** pairing data is `<state-dir>/<sensor-id>.pdata` (root-owned `0600` in
  `/etc/tudor`; a per-user copy can live in `~/.config/tudor`, `0600`). Contains the host
  private key. **Never print pdata/keys/tokens.** fprintd (root, `ProtectHome`) reads
  `/etc/tudor`; user probes use the `tudor.paths` fallback.
- **fprintd service** is sandboxed (`ProtectHome`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`) — anything it must read has
  to live outside `/home` (hence the pydrv stage under `/usr/lib`).

## Git / VCS
- Working branch: **`00bc-dev`** (off `origin/rev`). Other histories: `rev`, `relink`,
  `00bc`, `00bc-re`, `upstream` (`Popax21/synaTudor`) — `rev` and the relink line are
  **unrelated** git histories.
- **No push permission** to `origin` (`dmophir/synaTudor`); commits stay **local** unless
  explicitly told otherwise. Do not attempt to push. Use plain `git` over HTTPS.

## Safety (do not brick the sensor)
- **NEVER run** the OTP/permanent or destructive ops: `provision` (`0xe`),
  `take_ownership_ex2` (`0x4f`), `reset_ownership` (`0x10`), firmware `update`, storage/DB2
  `format` (`0x3f`/`0xa5`), `poke` (`0x8`). Enroll/verify/delete are non-destructive.
- **Wedge recovery:** a killed capture can leave a half-open TLS session (plaintext
  GET_VERSION → `15 03 03…` alert) or a stuck state (GET_VERSION → `0x0315`); clear with a
  USB `dev.reset()` + ~30 s idle. The driver's `open` already self-heals this.
- **Binary RE**, if needed, uses the local `re` subagent (`.opencode/agent/re.md`,
  gitignored); adapter/USB DLLs + r2 seed dumps are staged under `rev/` and the sandbox.
- Safety net: a btrfs `timeshift` snapshot predates this work; scheduled snapshots are also
  active.
