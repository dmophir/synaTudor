# Synaptics 06cb:00bc — Linux enablement notes

Working notes for making the Synaptics `06cb:00bc` fingerprint sensor
(Dell Latitude 7210 2-in-1 detachable) work on Linux. Read this first before
touching code — it captures prior art, the repo layout, the key unknowns, and
the agreed strategy so a fresh session can get up to speed fast.

Last updated: 2026-07-23

## TL;DR / current status
- Sensor: `06cb:00bc` (Synaptics), on a Dell Latitude 7210 2-in-1. Works on
  Windows via Dell's Synaptics driver; unsupported on Linux.
- Community state: **no working Linux driver and no active reverse-engineering
  effort for `00bc`.** It's on the libfprint "Unsupported Devices" wiki list
  with no RE-lead flag. Ubuntu bug #2144073 is a symptom report with no progress.
- This repo is a fork of `Popax21/synaTudor`. Branch `00bc` is a *blind* port of
  the `relink` approach from `00be`→`00bc` (DLL family swapped 104→103, Lenovo
  driver → Dell driver). It is **unverified and likely does not work as-is.**
- Agreed plan: **diagnose the protocol family before committing to a driver
  strategy.** See "Strategy".

## Hardware / environment facts
- USB ID: `06cb:00bc`. Internal sensor "product id" (from GET_VERSION) is a
  separate ASCII value — do not confuse with the USB PID.
- Tablet reachable over SSH as host `tablet` (configured in `~/.ssh/config`,
  key installed). Diagnostics run there; this repo lives on a macOS machine.
- Dev host: macOS. Tablet: Arch Linux + GNOME.
- Dell Windows driver used by the `00bc` branch:
  `Synaptics-Fingerprint-Sensor-Driver_3PFJG_WIN64_6.0.18.1103_A06.EXE`
  (self-extracting zip; DLLs `synaFpAdapter103.dll`, `synaWudfBioUsb103.dll`).

## Prior art / community findings
- **libfprint in-tree `synaptics` driver (bmkt / Match-on-Chip)** supports many
  `06cb:*` IDs including `00bd` — the ID *adjacent* to ours — but NOT `00bc`
  or `00be`. Adjacency of IDs does not imply same protocol.
- **synaTudor (`Popax21/synaTudor`)** targets the "Tudor" family `06cb:00be`
  (Thinkpad C740/Yoga). Two approaches:
  - `relink` branch (this fork's base): dynamically relinks the Windows "104"
    DLLs and shims the Windows API/WDF/WinBio surface. Fragile, version-coupled.
  - `rev` branch: full reverse engineering — protocol docs + a Python prototype
    driver + partial libfprint C driver + a TLS 1.2 implementation.
- **python-validity + open-fprintd**: userspace driver for older "Prometheus"
  sensors (`06cb:009a`, `138a:0090`…). Not `00bc`. A native rewrite (VCSFW) is
  in libfprint MRs !579/!619.
- No forks/MRs/entries target `00bc` anywhere found.

## Protocol landscape (which lineage is `00bc`? — the pivotal unknown)
Three candidates; only empirical testing on the device decides:
1. **bmkt / MoC** (like `00bd`) → easiest: add USB ID to libfprint `synaptics`.
2. **Tudor TLS** (like `00be`) → use/extend synaTudor `rev`; needs the sensor
   public key for `00bc`'s firmware version (see coupling below).
3. **"103"-family / other** → fresh RE (Windows USB capture + Ghidra).

The Tudor protocol (from `rev/proto.txt`): little-endian; USB endpoints
cmd(EP0)/resp(EP1)/interrupt; command set incl. `GET_VERSION(0x1)`,
`PAIR(0x93)`, `TLS_DATA(0x44)`; secure channel is TLS 1.2 ECDH-ECDSA-AES;
sensor cert verified against a hardcoded per-firmware ECC public key.

## This fork's layout / branches
- `origin/00bc` (current): blind 00be→00bc port. Experimental.
- `origin/relink` / `upstream` master: DLL relinking driver.
  - `libtudor/`  — PE loader + Windows API/WDF/WinBio shims + USB glue.
    Shims are written specifically for the **"104"** DLLs.
  - `cli/`, `tudor-host/`, `tudor-host-launcher/`, `libfprint-tod/`.
  - `libtudor/download_driver.sh` — fetches + extracts the Windows driver.
- `origin/rev`: reverse-engineering effort.
  - `rev/` — `proto.txt` (protocol), `rev.txt` (raw RE), IOCTL docs, Ghidra
    exports of the 104 DLLs.
  - `pydrv/` — Python prototype driver (`tudor/`), incl. TLS impl, pairing,
    bootloader, capture. Only ships sensor keys for firmware **10.1**
    (`pydrv/tudor/sensor/sensor_keys/10.1{,-kf}.tsk`) and bundled firmware
    (`mfw.tupd`, `iota.tupd`).
  - `libfprint/.../drivers/tudor.c` — partial C driver.

## Why the current `00bc` branch likely won't work as-is
- libtudor's Windows-API/WDF shims and all `rev` RE target the **"104"** DLLs;
  the branch loads **"103"** Dell DLLs → likely unshimmed API calls / different
  structs / possibly different wire protocol.
- Even if it links, the `rev` prototype is coupled to firmware version via the
  hardcoded sensor public key (only `10.1` bundled) and version-specific
  firmware blobs. `00bc`'s firmware/keys are unknown.
- Whether the Dell "103" driver even binds `00bc` (and via which stack) is
  unverified — must read its `.inf`.

## Decisions made (scope & resources)
- **Effort level: whatever it takes, including full reverse engineering.**
- **Access model:** SSH host `tablet` logs in as **root** (key-only). Agents may
  run diagnostics *and* installs/builds there. The real safeguards are the btrfs
  snapshot + the read-only sensor-command discipline, not the privilege model
  (bricking the sensor needs raw USB regardless).
- **Safety net:** timeshift on-demand btrfs snapshot `2026-07-23_13-47-14` taken
  before this work; scheduled snapshots also active.
- **Windows USB capture topology is undecided** and *deferred*. The sensor is
  internal to the tablet, so a Mac-hosted VM cannot see it; realistic options are
  a Windows VM on the tablet (qemu/kvm passthrough, capture via host `usbmon`/
  `tshark` or in-guest USBPcap) or dual-booting the tablet. Only pursue if the
  pydrv probe fails to identify the sensor.
- **Working branch:** `00bc-re` (off `00bc`). Do not build on the blind `00bc`
  branch until Phase 0b confirms the DLL family.
- **VCS:** no push permission to `origin` (`dmophir/synaTudor`); commits are
  local. Do not use the `gh` CLI (enterprise-only auth); use plain `git`.

## Strategy (diagnose first, then branch)
### Phase 0 — Diagnostics (cheap, reversible)
- 0a. `ssh tablet lsusb -v -d 06cb:00bc` → interface class, endpoints, bcdDevice;
  `dmesg`, installed libfprint/fprintd versions.
- 0b. Extract the Dell `.EXE` (it's a zip) on the Mac; read the `.inf` — which
  USB IDs it binds, which DLL/service serves `00bc`, is it truly 103 vs 104;
  diff DLLs vs the Lenovo 104 driver. Authoritative on the family question.
- 0c. Decisive probe: run `rev`-branch pydrv against the sensor
  (`sudo python -m tudor.driver usb --pid 0x00bc` → `info`). Valid GET_VERSION
  ⇒ Tudor-family + reveals firmware version; error/timeout ⇒ not Tudor.

### Phase 1 — Commit to a path
- **A. bmkt/MoC:** add `06cb:00bc` to libfprint in-tree `synaptics`, build git,
  test enroll/verify; confirm framing via short capture. Upstreamable.
- **B. Tudor TLS:** extend `rev` pydrv (preferred over relink); extract sensor
  public key for `00bc`'s firmware; wire pairing→TLS→enroll. Fix the relink
  branch only if 0b shows 104 DLLs bind `00bc`; else retarget DLL family and
  extend shims.
- **C. Other/103/ambiguous:** Windows VM + USBPcap capture of enroll/verify;
  Ghidra the Dell 103 DLLs; prototype in pyusb; port to a C libfprint driver.

### Phase 2 — Productionize
- Package as in-tree libfprint driver (MoC) or TOD/out-of-tree module (Tudor);
  udev + fprintd; validate enroll/verify/identify in GNOME; update libfprint
  wiki + Ubuntu bug #2144073.

## Open questions / unknowns
- Protocol family of `00bc` (Phase 0 resolves).
- `00bc` firmware version and whether we have/can extract its sensor public key.
- Whether Dell's 103 driver is relinkable with libtudor's 104-oriented shims.
- USB interface class (vendor WBDI vs HID) and endpoint layout.

## Phase 0 running log (diagnostics)
Append dated entries here as diagnostics run. Newest at the bottom.

### 2026-07-23 — read-only recon (pre-flight)
- **Sensor descriptor** (`lsusb -v -d 06cb:00bc`, tablet kernel 7.1.2):
  - Interface class **255 (Vendor Specific)**, `Driver=[none]` — nothing binds
    it in-kernel (no fprintd/usbhid conflict; no kernel-driver detach needed).
  - 1 interface, **3 endpoints**: `0x01` OUT bulk, `0x81` IN bulk, `0x83` IN
    interrupt. This maps exactly onto the documented Tudor layout
    (cmd / resp / event-poll) in `rev/proto.txt`. **Not** a HID device.
  - `bcdDevice 0.00`, `iProduct 0`, full-speed (12M), internal (Bus 001 Port 009).
  - ⇒ Structurally consistent with the **Tudor family** (Path B leading
    hypothesis). Firmware version still unknown — needs the `GET_VERSION` probe.
- **Tablet env:** Arch, Python **3.14.6** (bleeding edge; pydrv may need small
  fixups), `meson/ninja/gcc/git/yay` present. `pyusb` + `cryptography` **not yet
  installed**. No `libfprint`/`fprintd`/`libfprint-tod` installed at all.
- **Mac env:** `7zz` (sevenzip 26.02), `binwalk` 3.1.0, `cabextract` 1.11
  installed for driver extraction. Only `unzip` was present before.
- **Dell driver URL** live: HTTP 200, 13,566,112 bytes, `application/octet-stream`.
  Expected SHA1 (`libtudor/installer.sha`) = `b9941d62845f4ad324fda3ae5f542bc32f4a7ae2`.
- **Still TODO in Phase 0:** extract + read Dell `.inf` (0b); run pydrv `info`
  probe (0c) to get firmware version / product id / provision state.

## Key references
- Level1Techs write-up (this tablet, by the maintainer):
  https://forum.level1techs.com/t/success-with-linux-on-x86-tablet-dell-latitude-7210/237229
- Ubuntu bug #2144073:
  https://bugs.launchpad.net/ubuntu/+source/libfprint/+bug/2144073
- libfprint supported devices: https://fprint.freedesktop.org/supported-devices.html
- libfprint Unsupported Devices wiki:
  https://gitlab.freedesktop.org/libfprint/wiki/-/wikis/Unsupported-Devices
- Community catalog: https://github.com/jedbillyb/linux-fingerprint-drivers
- Upstream project: https://github.com/Popax21/synaTudor (branches: relink, rev)
