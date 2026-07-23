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
  the `relink` approach from `00be`→`00bc`. Superseded — see below.
- **PHASE 0 RESULT (2026-07-23): `00bc` is a Tudor-protocol sensor.** Dell's
  driver calls it **"Augusta"** (`synaWudfBioUsb103.dll`), and it runs firmware
  **10.1** — the *same* major.minor the `rev` prototype already has the sensor
  key for. The `rev` Python driver reads it end-to-end (GET_VERSION + IOTAs +
  sensor-key load all succeed). **Chosen path: extend the `rev` reimplementation**
  (Path B). The DLL-relink / blind-`00bc` approach is deprioritized — the `rev`
  path doesn't depend on the 103-vs-104 DLL question at all.
- **Next gate:** enrolling on Linux requires *pairing* (take-ownership), which
  re-keys the sensor and **breaks the existing Windows enrollment**. Needs
  explicit go-ahead before running (see "Strategy → Phase 1").

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
**RESOLVED (2026-07-23): candidate #2 — Tudor TLS.** See Phase 0 results below.
The three candidates considered were:
1. **bmkt / MoC** (like `00bd`) → ruled out.
2. **Tudor TLS** (like `00be`) → **CONFIRMED.** `00bc` ("Augusta", fw 10.1)
   speaks the Tudor protocol; the `rev` prototype already has its sensor key.
3. **"103"-family / other** → ruled out (103 is just the Augusta DLL gen; the
   on-wire protocol is Tudor).

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

## Why the blind `00bc` (relink) branch is deprioritized
- The relink approach shims Windows APIs for the "104" DLLs; the blind branch
  loads "103" (Augusta) DLLs, so shim compatibility was never guaranteed.
- Moot now: Phase 0 shows the **`rev` reimplementation talks to `00bc` directly**
  and doesn't load any Windows DLL, sidestepping the 103-vs-104 question entirely.
- The one real coupling in `rev` (per-firmware sensor public key) is **already
  satisfied**: `00bc` runs fw 10.1 and `sensor_keys/10.1-kf.tsk` matched.
- Keep the relink branches around only as a protocol reference / fallback.

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

### Phase 1 — Bring up the `rev` driver on `00bc` (CHOSEN: Path B)
Path A (bmkt/MoC) and Path C (fresh RE) are ruled out by Phase 0. Plan:
1. **Read-only protocol shakedown (no state change):** exercise more unencrypted
   commands via the `rev` driver (GET_START_INFO, storage-info, event-config
   reads) to check for Augusta divergences before any write.
2. **Pairing gate (DESTRUCTIVE to Windows enrollment — needs explicit OK):**
   run `pair` → `save_pdata` to take ownership and persist pairing data, then
   `init` to establish the TLS 1.2 session. This re-keys the sensor; the Windows
   fingerprint enrollment will stop working until re-paired under Windows.
3. **Capture/enroll:** exercise frame acquisition + enroll + verify via `rev`,
   watching for Augusta-specific differences (frame dims, IPL, event flow).
4. Fix any Augusta divergences in the `rev` code as they surface; add `00bc`
   (and likely `00a9`) to the driver's ID list.

### Phase 2 — Productionize
- Move from the Python prototype to the `rev` libfprint C driver
  (`libfprint/.../drivers/tudor.c`); package as a TOD/out-of-tree module;
  udev + fprintd; validate enroll/verify/identify in GNOME; update the libfprint
  wiki + Ubuntu bug #2144073.

## Open questions / unknowns
- ~~Protocol family of `00bc`~~ — RESOLVED: Tudor ("Augusta", fw 10.1).
- ~~Firmware version / sensor key availability~~ — RESOLVED: fw 10.1, key
  `10.1-kf.tsk` present and loads.
- Do the **stateful** Tudor operations (pair, TLS, capture, enroll, DB2) behave
  identically on Augusta `00bc`, or are there divergences vs Tudor `00be`?
- Can Windows fingerprint be restored (re-paired) after we take ownership on
  Linux? (Assumed yes via the Windows driver, but unverified.)
- Does sibling `06cb:00a9` share fw/keys (bonus coverage)?

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
### 2026-07-23 — Phase 0 results (family CONFIRMED: Tudor / "Augusta")
- **Dell driver `.inf`** (`synaWudfBioUsbUwp.inf`, DriverVer 6.0.18.1103,
  09/03/2024; folder `DellAugusta-103_v6_0_18_1103_Signed_uwp_x64_Inf`):
  - Binds exactly **`USB\VID_06CB&PID_00A9`** and **`USB\VID_06CB&PID_00BC`**.
    So `00bc`'s sibling under the same driver is `00a9`.
  - Sensor codename **"Augusta"**; DLL generation **103**
    (`synaWudfBioUsb103.dll` UMDF driver over WinUSB; `synaFpAdapter103.dll`
    WinBio Sensor/Engine/Storage adapter). **Same WBDI/UMDF architecture as
    Tudor (104)** — Augusta is a sibling generation, not a different stack.
  - ⇒ The blind `00bc` branch's DLL *names* (103) were right for this driver;
    the open question was only shim/protocol compat — now moot, see below.
- **`GET_VERSION` probe** (raw, read-only, via `rev` `tudor.comm`):
  `status=0x0000`, **fw=10.1.2884577**, product_id=`0x41 'A'` (PROD_ID5),
  sensor_id=`22eb371d6299`, provision_state=**3 (provisioned to Windows)**,
  flags ⇒ advanced_security present, **key_flag set**.
- **Full `Sensor(comm)` construction** (read-only; GET_VERSION + IOTA reads +
  key load, no pairing/TLS): **succeeds**. `cfg_ver=3472.0.2`, `wbf_param=0x8`,
  `pub_key_loaded=True` (bundled `sensor_keys/10.1-kf.tsk` matched).
- **Conclusion:** `06cb:00bc` speaks the Tudor protocol; every read-only,
  pre-TLS layer works with the `rev` prototype unchanged, and the required
  sensor public key is already bundled. **Path B confirmed.** Pivotal unknown
  (§"Protocol landscape") is **RESOLVED: Tudor family.**
- **Not yet tested (stateful, deferred to Phase 1):** pairing/take-ownership,
  TLS session establishment, frame capture/enroll, DB2 storage. Pairing is
  **destructive to the Windows enrollment** and needs explicit consent.
- Probe scripts live on the tablet at `/root/synatudor/pydrv/probe_00bc.py`
  and `probe2_00bc.py`; the `rev` pydrv tree is at `/root/synatudor/pydrv/`.
  Dell driver extracted on the Mac under the opencode temp dir.
- **Session end status:** only read-only ops were run (GET_VERSION, IOTA reads,
  USB reset). **No stateful/destructive command was issued** — the sensor is NOT
  re-paired, and the **Windows fingerprint enrollment remains intact.** Phase 1
  (pairing → TLS → enroll) is intentionally deferred pending explicit consent,
  since pairing takes ownership and breaks the Windows enrollment.

### 2026-07-23 — Phase 0 addenda (reference details)
- **Dell package contents** (extracted from the pinned EXE; SHA1 in
  `libtudor/installer.sha`): `synaWudfBioUsb103.dll` (1.4 MB, UMDF USB driver —
  holds the protocol/TLS/IPL logic **and** embedded per-fw sensor keys),
  `synaFpAdapter103.dll` (191 KB, WinBio adapter), `synaWudfBioUsbUwp.inf`,
  `synaumdf.cat`, plus Dell wrappers (`DellInstaller_x64.exe`, `mup.xml`,
  `package.xml`). **No separate firmware/cert/key blobs** — they live inside
  the DLLs. Binaries are re-obtainable via the pinned URL+SHA, so they are not
  committed.
- **RE reference for Augusta divergences:** `synaWudfBioUsb103.dll` is the
  disassembly target (analog of the `rev/` Ghidra exports of the `104` DLL).
  This is also where other-firmware sensor keys would be extracted from, if ever
  needed (fw 10.1 is already covered by `sensor_keys/10.1-kf.tsk`).
- **Known-good `GET_VERSION` sample** (06cb:00bc, fw 10.1) for decoding the
  `????` fields in `rev/proto.txt`:
  `0000d083255ce1032c000a01014101c1000022eb371d62990fa1000000000100000000000003`
  (status `0000`; build `2c003 -> 2884577`; major `0a`; minor `01`;
  product `41 'A'`; id `22eb371d6299`; flags1 `0f`, flags2 `a1`; prov `03`).
- **Reproduce anytime** with the read-only probes:
  `sudo python pydrv/diag/probe_getversion.py 0x00bc` (pyusb-only) or
  `sudo python pydrv/diag/probe_sensor.py 0x00bc` (rev `Sensor`).
- **Env/tooling:** tablet Python **3.14.6** ran the read path clean (pyusb
  1.3.1, cryptography present); the TLS/stateful paths (which lean on
  `cryptography`) are **untested**. Mac has `7zz`, `binwalk`, `cabextract`.
- **Operational gotcha:** `python -m tudor.driver` fails to import unless
  `matplotlib` is installed (pulled via `drvcmd/capture.py`); core sensor ops
  don't need it — the `diag/` probes avoid the CLI entirely.
- **Repo/branch note:** `rev` and the relink line (`relink`/`00bc`/`00bc-re`)
  are **unrelated git histories** (no merge-base). Path B development lives on
  the `rev` line: branch **`00bc-dev`** (off `origin/rev`), with the Phase 0 doc
  commits cherry-picked over. `00bc-re` is kept as a bookmark.

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
