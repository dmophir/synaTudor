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
- **Status (2026-07-23): Linux now OWNS the sensor (Phase 1c done).** Pairing
  (`PAIR 0x93`) + full TLS 1.2 session + encrypted commands all work on Augusta
  with **unmodified** pydrv; frame geometry = 104×86, 16bpp. Pairing data saved
  at `/etc/tudor/22eb371d62990000.pdata`. **Windows fingerprint enrollment is now
  broken** (recoverable via Windows re-enroll). Next: **1d** — capture frames +
  reconstruct an image (IPL). See Phase 1 running log.

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
Path A (bmkt/MoC) and Path C (fresh RE) are ruled out by Phase 0.

- **1a. Read-only protocol shakedown** — DONE (PASS; see running log). All
  pre-TLS commands match Tudor framing.
- **1b. Capture-to-PGM tooling staged** — DONE (`pydrv/tools/capture_pgm.py`),
  not run.
- **1b.6. Verify Augusta's HS (host-signing) key** — DONE (read-only RE).
  RESULT: **pydrv's `hskey.pem` is correct for Augusta; no swap needed.** Proven
  by extracting the 104 driver and diffing the HS-key derivation chain
  (`palGenHSPrivKey`/`palSymKeyGen`/`palPRF` + inline seed `b34944…`) — identical
  between 103 and 104 (normalized disasm diff = 0). See running log. Both keys
  pydrv needs (sensor pubkey + HS key) are now confirmed for Augusta ⇒ the
  crypto/key risk for `pair`/`init` is eliminated.
- **1c. Pairing gate (DESTRUCTIVE; needs explicit OK) — gated on 1b.6:**
  snapshot (OS) → `pair` with full COMM logging (capture `PAIR 0x93` req/resp) →
  success: `save_pdata` + `fprintd_setup` → `init` (TLS; sensor-cert verify
  expected OK given key match) → 1d. Failure: STOP, diagnose (rejection ⇒ HS key
  still wrong ⇒ revisit 1b.6); Windows binding expected intact on rejection.
- **1d. Image-capture validation** — capture frames + reconstruct (104
  `libnative` IPL) → write PGM; **also save raw frames**. Judge fingerprint
  quality. Garbage ⇒ extract Augusta `tudorIpl*` from the 103 driver, rebuild
  `libnative`. Tune `FRAME_ACQ` flags if capture stalls.
- **1e. Consolidate** — add `06cb:00bc` (and likely `06cb:00a9`) to pydrv
  defaults + the libfprint `id_table`; record samples/deltas in the running log.

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

## Pairing, ownership & reversibility
How pairing works and whether taking ownership on Linux is permanent.

**Provenance / confidence legend** (be precise about where each claim comes from):
- `[RE-104]` — from Popax21's RE of the **104/Tudor** Windows driver
  (`rev/rev.txt`); *inferred* for our 103/Augusta sensor, not dynamically tested.
- `[STR-103]` — independently corroborated by a **read-only string scan of the
  actual `synaWudfBioUsb103.dll` (Augusta)** on 2026-07-23 (see the Phase 1 log).
- `[ASM-103]` — corroborated by **disassembly** (radare2/objdump) of the 103 DLL:
  imports and/or code confirmed.
- `[PROBE-00bc]` — directly observed on our sensor via read-only probes.
- `[UNVALIDATED]` — not confirmed by us on 103, dynamically, or at all.

Nothing here has been validated by *actually pairing* — the destructive step is
still un-run.

- **Pairing is a re-doable, host-side credential binding.** `sensor.pair()`
  issues only `PAIR (0x93)`; it requires provision state 3 and generates a fresh
  ECC host keypair each time. `[RE-104]` + code. USAGE: *"you can pair the sensor
  as many times as you want"* — `[RE-104]`/author experience on `00be`,
  `[UNVALIDATED]` on `00bc`.
- **Pairing ≠ provisioning.** Provision state `3 = provisioned` `[PROBE-00bc]`;
  `pair()` requires it but never changes it `[RE-104]`+code.
- **Host-side pairing storage confirmed on 103** `[STR-103]`: the driver contains
  `CBiometricDevice::DoPairing/DoUnpairing/OnResetOwnership/ProcessPairing`, the
  registry path `Synaptics\PairingData`, `PairingInProcess`/`UnairingInProcess`
  flags, and pairing data is **DPAPI-encrypted** (`CryptProtectData`/
  `CryptUnprotectData`). There is also an on-device **"host partition"** that
  stores (encrypted) pairing info (`_isHostPartitionHasPairingInfo`,
  "update ... pairing data in host partition"). Basic vs advanced pairing paths
  exist (`_tudorSecurityBasicPairing`/`_tudorSecurityAdvancedPairing`); our
  sensor is advanced-security `[PROBE-00bc]`.
- **What breaks when we pair on Linux:** the host binding is overwritten, so
  Windows' stored pairing goes stale and the Windows-enrolled templates (bound to
  that pairing) are lost. **Expected NOT permanent / NOT a brick:** Windows
  re-pairs on next Windows Hello setup (or reinstall + Dell driver); you re-enroll
  fingerprints. `[RE-104]` — plausible but `[UNVALIDATED]` end-to-end on `00bc`.
- **Restore path is "Windows re-pairs," not "Linux unpairs":** pydrv `unpair()`
  is essentially a no-op reset `[RE-104]`+code.
- **⚠ OTP-backed ownership is the genuinely permanent/finite operation** `[STR-103]`:
  the 103 driver references `VCSFW_CMD_PROVISION`, `VCSFW_CMD_TAKE_OWNERSHIP_EX2`,
  `VCSFW_CMD_RESET_OWNERSHIP`, and the result `VCS_RESULT_SENSOR_OUT_OF_OTP_OWNERSHIP`
  ("OTP" = one-time-programmable ⇒ a finite, permanent resource). These
  ownership/provision ops are **distinct** from `PAIR (0x93)`; `pydrv.pair()`
  never issues them. This is why the "never run" list below matters.
- **Failure count is a HOST-side Windows throttle, not a device fuse.** Confirmed
  on 103 by disassembly `[ASM-103]`: the driver imports `RegOpenKeyEx`/
  `RegQueryValueEx`/`RegSetValueEx`/`RegCreateKeyEx`/`RegDeleteValue` (host-side
  registry storage), `CryptProtectData`/`CryptUnprotectData` (DPAPI), and
  `GetTickCount`/`GetSystemTimeAsFileTime` (tick timing). The failure counters
  (`SetOwnershipFailureCount`, `DeviceInitializeFailures`, `UpdateFirmwareFailureCount`,
  `SensorLockFailureCount`, `IptProvisionFailureCount`) are read/written **as a
  group** in a stats routine at `~0x18000bf00`, and `GetTickCount` is exposed via
  a thin wrapper (`fcn.180062090`) used by several callers — consistent with
  tick-based aging.
  - **NOT confirmed on 103** `[UNVALIDATED]`: the exact arithmetic from `[RE-104]`
    — *"reset if older than ~30000 ticks, decrement if >4, increment if <5."* The
    only literal `30000`/`0x7530` in the binary is a **DB/pipe timeout**
    (`mov dword [rsp+0x38], 0x7530` in a `tudorCmdFormat`/`DatabaseErase` routine),
    **not** the stats-aging threshold. So do not cite "30000 ticks" as fact; the
    aging/decrement arithmetic lives deeper in the call tree and was not traced.
  - **Conclusion still holds:** the counters are host-side registry state (hence
    resettable and wiped by a Windows reinstall) and are **not maintained on
    Linux** (pydrv never reads/increments them). Only the precise reset cadence
    is unverified.
- **Device-side pairing-failure fuse:** none documented; the sensor does have NVM
  and a `SensorLockFailureCount` / `VCS_RESULT_SENSOR_OUT_OF_OTP_OWNERSHIP` exist,
  so a device-side lock around *ownership/OTP* is plausible — but that is the
  ownership path we avoid, not plain pairing. `[STR-103]` names, `[UNVALIDATED]`
  behavior.
- **Operational rule:** if `pair`/`init` errors, **STOP and diagnose** rather
  than retrying, to avoid any lockout path (Windows-side or unknown device-side).
- **Commands we will NEVER run** (deeper, potentially permanent / OTP-consuming):
  `PROVISION (0xe)`, `TAKE_OWNERSHIP_EX2 (0x4f)`, `RESET_OWNERSHIP (0x10)`,
  firmware `update`. `sensor.pair()` only issues `PAIR (0x93)`.

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

## Phase 1 running log
Newest at the bottom. Phase 1 = bring up the rev pipeline on Augusta through to
a captured fingerprint image over TLS. The rev libfprint driver (`tudor.c`) is
an **FpImageDevice** that embeds Python and calls `frame_capturer.capture_images`
— i.e. capture raw images, **match on host** (NBIS); no on-chip enroll/DB2. So
the pivotal Phase 1 test is "can we capture a usable image over TLS?".

### 2026-07-23 — 1a read-only shakedown (PASS, no divergence)
Tool: `pydrv/diag/shakedown_00bc.py` (read-only). Results on `06cb:00bc`:
- `GET_START_INFO (0x19)`: `status=0x0000`; start_type=0x00, reset_type=0x03,
  start_status=0x201.
- `STORAGE_INFO_GET (0x3e)`: `status=0x0000` **pre-TLS** (works unencrypted);
  raw shows ~3 storage partitions.
- `remote_tls_status` (ctrl `0x14`): `False` (not in a session — clean).
- **IPL IOTA (`0x1a`): 68 bytes**, `abc20200bec002005b1b00000a0000004400560068...`
  — this is the data fed to `libnative` for image reconstruction in 1d.
- ⇒ Every pre-TLS command matches Tudor framing; no Augusta divergence yet.

### 2026-07-23 — 1b tooling staged (no sensor writes)
- Added `pydrv/tools/capture_pgm.py` (+ `tools/README.md`): headless
  pair + capture-to-PGM (no matplotlib/X). Destructive `--pair` gated behind
  `--pair --yes`. **Not run yet.** `py_compile` clean; not staged on the tablet
  until the 1c go-ahead.
- **STOP POINT:** paused before 1c (pairing/take-ownership), which is
  destructive to the Windows enrollment. Awaiting explicit go/no-go. Sensor is
  still untouched (only read-only ops run this session).

### 2026-07-23 — permanence/failure-count investigation (RE)
- Investigated whether pairing is permanent and where the failure count lives
  (see the new "Pairing, ownership & reversibility" section for details).
- Conclusion: **taking ownership on Linux is reversible** — Windows re-pairs
  after reinstall + Dell driver; only the current templates are lost. The
  ownership/init **failure count is a host-side Windows registry throttle**
  (auto-ages after ~30000 ticks, self-decrements, wiped on reinstall) and is
  **not maintained on Linux**; no device-side pairing-failure fuse is documented.
- This **corrects** the earlier "semi-permanent lockout" caution above — the
  residual rule is just: stop-and-diagnose on any pair/init error.

### 2026-07-23 — 103 binary validation (objdump + radare2)
Independent, read-only analysis of the extracted `synaWudfBioUsb103.dll`
(Augusta) to check the pairing/failure-count claims (previously only `[RE-104]`).
- **String scan** confirmed: `CBiometricDevice::DoPairing/DoUnpairing/
  OnResetOwnership/ProcessPairing`, registry path `Synaptics\PairingData`,
  DPAPI (`CryptProtectData`/`CryptUnprotectData`), basic/advanced pairing,
  on-device "host partition" pairing copy, and OTP ownership
  (`VCSFW_CMD_{PROVISION,TAKE_OWNERSHIP_EX2,RESET_OWNERSHIP}`,
  `VCS_RESULT_SENSOR_OUT_OF_OTP_OWNERSHIP`).
- **Imports (`objdump -p`)** confirmed host-side mechanism: `RegOpenKeyEx*`,
  `RegQueryValueEx*`, `RegSetValueEx*`, `RegCreateKeyEx*`, `RegDeleteValueA`;
  `CryptProtectData`/`CryptUnprotectData`; `GetTickCount`,
  `GetSystemTimeAsFileTime`, `QueryPerformanceCounter`.
- **Disassembly (radare2)**: failure counters read/written as a group at
  `~0x18000bf00` (xrefs to the property-name strings at `0x18000adXX`/`0x18000bfXX`);
  `GetTickCount` wrapper at `fcn.180062090`.
- **Retraction:** the "reset if older than ~30000 ticks" figure is **NOT** the
  stats-aging threshold on 103 — the sole `0x7530` immediate (`0x1800a9106`) is a
  DB/pipe timeout in a `tudorCmdFormat`/`DatabaseErase` routine. The exact aging/
  decrement arithmetic was not traced; treat it as unverified.
- **Net:** host-side/registry/DPAPI/tick architecture and OTP-ownership-is-the-
  permanent-op are validated on 103; the precise failure-count reset cadence is
  not. Pairing reversibility conclusion unchanged.

### 2026-07-23 — pre-1c key provenance check (103 vs pydrv keys)
Read-only comparison of the keys pydrv relies on vs. the actual 103 Augusta
binary, to predict whether `pair`/`init` will work before the destructive step.
- ✅ **Sensor public keys MATCH.** Both `10.1.tsk` and `10.1-kf.tsk` sensor-key
  coordinates are embedded in `synaWudfBioUsb103.dll` (little-endian) at a key
  table `~0x130de3–0x130f2a`. ⇒ `init()`/TLS **device-cert verification predicted
  to work**; this path is de-risked. `[ASM-103]`
- ✅ **HS (host-signing) key MATCHES — pydrv's `hskey.pem` is correct for
  Augusta.** (This corrects an earlier false alarm.) The host key is *derived*
  (`palGenHSPrivKey` → `palSymKeyGen` → `palPRF`, TLS 1.2 PRF via
  `BCryptDeriveKey`, label `HS_KEY_PAIR_GEN`) from an inline 32-byte seed. That
  seed (`b3494469…4daee823`) and the **entire derivation chain are byte-identical
  between the 103 (Augusta) and 104 (Tudor) drivers** (normalized disasm diff =
  0). ⇒ identical derived HS key = pydrv's bundled `hskey.pem` (`priv e8a2…`).
  Note: `rev.txt`'s `palSynaKmGet` `717c…` is **not** the HS-key input (red
  herring); searching for it earlier produced a false "differs" conclusion. `[ASM-103]`
- ✅ **Derivation machinery present in 103** `[ASM-103]`: strings
  `palSynaKmGet`, `palSymKeyGen`, `HS_KEY_PAIR_GEN`, `palGenHSPrivKey`,
  `_tudorSecuritySignHPubK`, `_tudorSecurityGenHostKeyPair`. So the *algorithm*
  matches; only the seed differs — recovering Augusta's HS key is tractable and
  **verifiable** (known 104 pair: seed `717c…` → priv `e8a2…`).
- ℹ️ A wrong-HS-key `pair` attempt is expected **non-destructive** (bad host-cert
  signature just fails validation; existing Windows binding untouched).
- **Decision:** RE-first — recover Augusta's HS key (new step 1b.6) *before* any
  pairing attempt.

### 2026-07-23 — 1b.6 HS-key recovery: progress + effort reality
Read-only RE of `synaWudfBioUsb103.dll` (radare2) to recover Augusta's HS key.
- **Augusta HS-key seed EXTRACTED** `[ASM-103]`. `palGenHSPrivKey`
  (`fcn.1800724d0`) builds the 32-byte key-material inline (byte movs into a
  stack buffer, len `0x20`) then calls the KDF with the `HS_KEY_PAIR_GEN` label.
  Augusta seed =
  `b3494469 d36e4861 9f0b2c7b d3920374 9f0371df 1f2ea374 2b7b05bb 4daee823`.
  Confirmed **different** from the 104 seed (`717cd72d…`).
- **KDF identified** `[ASM-103]`: `palGenHSPrivKey` → `palSymKeyGen`
  (`fcn.1800779f0`) → `palPRF` (`fcn.1800743b0`), and `palPRF` uses
  **`BCryptDeriveKey` with `TLS_PRF` + `SHA256`** ⇒ the derivation is the
  **TLS 1.2 PRF** `P_SHA256(secret, label‖seed)`. The derived 32 bytes are
  imported directly as the ECC private scalar.
- **Not yet reproduced:** brute-forcing standard constructions
  (P_SHA256/HKDF/SP800-108/HMAC/SHA over km+label+ctx variants, 80 combos) did
  **not** reproduce the known 104 pair (seed `717c…` → priv `e8a2…`). Likely
  cause: the exact `(secret,label,seed)` argument layout to `palPRF` needs
  tracing (args at `0x180077e97` come from several locals), **and/or** the 104
  seed transcribed in `rev.txt` is slightly off.
- **Recommended next step:** eliminate the transcription risk by extracting the
  **104 seed directly** from the Lenovo 104 driver (`libtudor/download_driver.sh`
  → `synaWudfBioUsb104.dll`, `palGenHSPrivKey`), giving a self-consistent
  104 (seed→`e8a2…`) validation pair; then reproduce the exact PRF input layout,
  validate on 104, and apply to the Augusta seed to get Augusta's HS key.
- **Status:** STOP before 1c (destructive). Sensor untouched. HS key not yet
  recovered — pairing must wait until it is (or until we accept an empirical,
  non-destructive-if-rejected pair probe).

### 2026-07-23 — 1b.6 RESOLVED: pydrv's HS key is CORRECT for Augusta
Downloaded the Lenovo 104 driver (`r19fp02w.exe`, SHA1 `7450e2f9…`, matches
`libtudor/installer.sha`), extracted `synaWudfBioUsb104.dll`, and compared the
HS-key derivation to the 103 Augusta driver `[ASM-103]`+`[ASM-104]`:
- The **inline HS-key seed is byte-identical** in both drivers'
  `palGenHSPrivKey`: `b3494469 d36e4861 9f0b2c7b d3920374 9f0371df 1f2ea374
  2b7b05bb 4daee823`. (So `rev.txt`'s `palSynaKmGet` `717c…` is **not** the
  HS-key input — a red herring; the earlier "seed differs / HS key differs"
  concern was a FALSE ALARM.)
- **The whole derivation chain is identical across 103 and 104** — normalized
  disassembly diff = 0: `palGenHSPrivKey` (138 insns), `palSymKeyGen` (210),
  `palPRF` (281). Same seed + same label (`HS_KEY_PAIR_GEN`) + same KDF
  (TLS 1.2 PRF via `BCryptDeriveKey`) ⇒ **identical derived HS key.**
- Since the 104 output is pydrv's bundled `hskey.pem` (`priv e8a2…`),
  **pydrv's `hskey.pem` is valid for Augusta. No HS-key swap is needed.**
- (Note: we did not numerically reproduce the exact PRF argument layout — a few
  standard constructions didn't match `e8a2…` — but code-level equivalence
  across the two drivers is a stronger proof and makes reproduction unnecessary.)
- **Net for 1c:** both keys pydrv relies on are now confirmed correct for
  Augusta — sensor public key (fw 10.1, matched in 103) and the HS host-signing
  key (derivation identical). The crypto/key risk for `pair`/`init` is
  **eliminated**; remaining 1c unknowns are only generic protocol behavior
  (cert sizes, TLS handshake quirks) that pydrv already handles for 104.

### 2026-07-23 — pre-1c pairing-crypto dry-run (PASS, Python 3.14)
Before the destructive pair, validated that pydrv's *stateful* crypto path runs
on the tablet (previously only the read path was exercised). Tool:
`pydrv/diag/dryrun_pair_crypto.py` (no sensor I/O). On Python **3.14.6** /
`cryptography` **49.0.0**:
- `load_hs_key` OK (secp256r1); `create_host_cert` OK (ECDSA sign, sig_len 71);
  400-byte `SensorCertificate` `tobytes`/`frombytes` round-trip OK; host-cert
  signature **self-verifies** against the HS public key; `SensorPairingData`
  save/load round-trip (868 B) OK. → "ALL PAIR-CRYPTO DRY-RUN CHECKS PASSED".
- ⇒ The Python-3.14/`cryptography` risk on the pair/TLS path is retired for the
  crypto+serialization portion. `pair` is now the correct next step.
- Re-answer to "is `pair` still correct?": **yes** — it is unavoidable (Linux
  must own the sensor to capture/enroll) and now maximally de-risked; only the
  non-destructive crypto dry-run was worth doing first, and it passed.

### 2026-07-23 — 1c COMPLETE: paired + TLS session works on Augusta
Executed the destructive pairing gate with the controlled tool
`pydrv/tools/pair_00bc.py` (COMM/TLS logged; host key saved before + raw PAIR
response saved around the single destructive command).
- Fresh OS snapshot `2026-07-23_16-52-42` (ondemand) taken first.
- **`pair` SUCCEEDED**: `PAIR (0x93)` → `status=0x0000`; sensor **accepted our
  host cert** ⇒ empirically confirms pydrv's HS key is correct for Augusta.
  802-byte response parsed; device cert (type 0) returned.
- **`init-test` (TLS) SUCCEEDED** end-to-end (unmodified pydrv):
  - Device cert **verified** against sensor key `10.1-kf` ⇒ empirically confirms
    the sensor-key match.
  - Full **TLS 1.2 mutual-auth handshake**, negotiated cipher
    **`TLS_ECC_AES256_GCM_SHA384` (0xc02e)**; encrypted ApplicationData commands
    (frame-state-get `0x82`, event-config `0x86`) work.
  - **Frame geometry: 104×86, pixel_bits=16** (x_size=104, y_size=86).
  - Clean `uninitialize` (TLS close_notify both ways).
- **Post-pair health**: `GET_VERSION` still `status=0x0000`, fw 10.1,
  `prov_state=3` — sensor healthy, not bricked.
- **Windows enrollment is now BROKEN** (as expected; recoverable by re-enrolling
  under Windows — re-pairing overwrites our binding).
- **Artifacts (tablet only; secrets not printed/copied off):**
  `/etc/tudor/22eb371d62990000.pdata` (868 B, 0600) + backup
  `/root/synatudor/1c/pdata_22eb371d62990000.tpd`; `hostpriv_*.bin` (68 B, 0600);
  `pair_resp_*.bin` (802 B); logs `1c_pair.log`, `1c_init.log`.
- **Sensor state: OWNED BY LINUX.** Pair/TLS/secure-command path confirmed on
  Augusta with no code changes. Remaining for 1d: `FRAME_ACQ`/`FRAME_READ` +
  IPL reconstruction (104×86, 16bpp) into a usable image.

### 2026-07-23 — 1d capture attempt: BLOCKED at FRAME_READ (0x0689)
First finger capture via `pydrv/tools/capture_pgm.py --capture 5` (over TLS):
- `init`/TLS OK; finger-remove event OK; `FRAME_ACQ (0x80)` **succeeded**.
- **`FRAME_READ (0x7f)` failed: `status 0x0689`** on the first frame ⇒ no raw
  frames captured; IPL path not reached. (Not the IPL question — capture itself
  diverges.)
- Root cause is under-documentation: `rev/proto.txt` marks almost all
  `FRAME_ACQ`/`FRAME_READ` fields `????` and the flags "pure guesswork";
  `rev.txt` shows the Windows driver hides frame capture behind native `vfm*`
  IOCTLs (`vfmUtilCaptureImage`/`vfmCaptureStart`/`vfmCaptureProcess`) it never
  fully decoded. Windows uses **num_frames=1** and **capture flags 7 or 15**
  (pydrv used num_frames=5 + different flag bytes).
- ⇒ **Next: RE the frame-capture command builders** (offline, no finger cost):
  decode `FRAME_ACQ (0x80)` flags + `FRAME_READ (0x7f)` request format from the
  103 (or 104) DLL (radare2), fix `capture.py`, then do one more finger capture.
  Empirical flag-tweaking is possible but each try needs a finger press, so
  RE-first is preferred.
- Artifacts: `/root/synatudor/1d/1d_capture.log`, `run.out`. Sensor healthy;
  pairing/TLS unaffected (this is purely the frame-read command).

### 2026-07-23 — frame-command RE (104 DLL): FRAME_READ ok, FRAME_ACQ is the gap
RE of the frame commands in `synaWudfBioUsb104.dll` (radare2; identical protocol
to 103), via the command builders (opcode set by `fcn.180087530`, sent by
`fcn.180087000`):
- **`FRAME_READ (0x7f)`** builder `fcn.180083b10` (`tudorCmdFrameRead`): 9-byte
  request — `[0]=0x7f`, `[1-2]=seq` (from `sensor->+0x90`), `[3-4]=0`,
  `[5-6]=0xffff`, `[7-8]=3`. **Matches pydrv's `capture.py` exactly** ⇒ not the
  problem.
- **`FRAME_ACQ (0x80)`** builder `fcn.180083e80` (`tudorCmdFrameAcq`): a
  **multi-mode, record-based** request (~25 bytes) — writes a header
  (`[1-4]`, `[5-8]=num_frames`) then appends parameter *records* whose content
  depends on args (`var_50h` branch; a 1/2/3 mode selector) with observed
  constants `0x0c (12)`, `0x14 (20)`, `2`, `1`, `8`. **pydrv sends a flat 17-byte
  struct** and stops at offset `0x10` — it omits the trailing records
  (`0x11..0x18`). ⇒ **This is why `FRAME_READ` returns `0x0689`:** the sensor's
  capture mode is misconfigured by an incomplete `FRAME_ACQ`.
- Windows uses **num_frames=1** and **capture flags 7/15** (per `rev.txt`).
- **Blocker:** the exact `FRAME_ACQ` bytes are arg/branch-dependent and not
  reliably reconstructable from static disasm alone. Cleanest ground truth is a
  **Windows USB capture** (USBPcap) of one real capture — the deferred fallback,
  now justified. Alternative: deeper static arg-tracing, or best-effort empirical
  (costs finger presses).

### 2026-07-23 — 1d frame-capture RE (subagent fanout) + still blocked at 0x0689
Used the `re` (Opus) subagent fanout to RE the frame-capture commands. **Fanout
works well in opencode.** Findings (all cross-checked 103≡104):
- **`FRAME_ACQ (0x80)` is multi-mode.** pydrv's original flat 17-byte request was
  already a valid "mode 2" shape; a 25-byte "mode 3" also exists. Patched
  `capture.py` to send the exact **25-byte mode-3** request
  (`80 01000000 <num> 0100 00 08 01 01 00 00 0100 00 0c 1400 02 00`). On device it
  is **ACCEPTED (status 0x0000)** — but does not fix the read.
- **`FRAME_READ (0x7f)` bytes + seq are provably correct**: 9-byte req
  `7f <seq> 0000 ffff 0300`; seq from `sensor+0x90` (reset to 0 by ACQ, ++ only on
  success) ⇒ first read = **seq 0**, exactly what pydrv sends. Not malformed.
- **ioctl `0x6a` = a cached interrupt-EP read** (== pydrv `get_event_data()` on
  EP 0x83). **No extra bus command exists between `FRAME_ACQ` and `FRAME_READ`**
  on 103. (104-only extra = host-side WinUSB `SET_POWER_POLICY` pipe-timeout, not
  a wire transfer.) Readiness gate = interrupt `[0]==2` AND frame-index changed.
- **Status `0x0689`** = unmapped raw sensor "0x6xx-band" error (→ driver maps to
  0xca); i.e. the sensor rejecting the read as a **capture-state/timing**
  condition, not a byte error.
- **On-device result:** with mode-3 ACQ accepted AND a frame latched
  (interrupt `02000000000101`, byte0=2, idx=1), `FRAME_READ(seq=0)` STILL returns
  **0x0689**. So static RE has **plateaued**: ACQ mode, READ bytes, seq, and
  readiness all match the Windows driver, yet the sensor rejects the read.
- **Next step (pending, needs a finger press):** on-device experiment
  `pydrv/diag/frame_read_probe.py` — after one press, sweeps `FRAME_READ` seq 0..7
  (raw) and logs the interrupt sequence, to see if *any* seq is accepted or if the
  block is deeper (mode/timing/state). If that's inconclusive, escalate to a
  Windows dynamic capture (Frida on the friend's identical tablet — the frame
  cmds are TLS-encrypted, so passive USBPcap won't suffice) for ground-truth
  timing/sequence.

**Operational notes for next session:**
- Sensor is currently HEALTHY (GET_VERSION 0x0000, prov 3); pairing intact;
  Windows enrollment broken (from 1c, recoverable via Windows re-enroll).
- Failure recovery: a *killed capture* can leave a **half-open TLS session** →
  plaintext commands then return a TLS alert record (`15 03 03 …`); clear it with
  a USB `dev.reset()` + ~20s idle wait. A *failed `FRAME_ACQ`* can leave the
  sensor stuck (GET_VERSION → `0x0315`); also self-recovers after idle timeout.
- `pydrv/diag/`: `probe_getversion.py` (pyusb-only health check), `probe_sensor.py`,
  `shakedown_00bc.py`, `dryrun_pair_crypto.py`, `frame_read_probe.py`.
  `pydrv/tools/`: `pair_00bc.py` (pair/init-test), `capture_pgm.py` (capture).
  Pairing data at `/etc/tudor/22eb371d62990000.pdata`.

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
