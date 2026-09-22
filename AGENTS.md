# Agent onboarding

This is a fork of `Popax21/synaTudor` being used to bring the Synaptics
`06cb:00bc` fingerprint sensor (Dell Latitude 7210 2-in-1) up on Linux.

**Before doing anything, read [`docs/00bc-porting.md`](docs/00bc-porting.md)**
(source of truth: prior art, branch layout, phased strategy, running log) and its
companion [`docs/frame-capture-re.md`](docs/frame-capture-re.md) (detailed,
independently-validated binary RE of the capture protocol). Keep both up to date.

## Current status (2026-07-24)
- **DONE:** Linux OWNS the sensor — pairing + TLS 1.2 + encrypted command channel
  all work on `06cb:00bc` (Augusta, fw 10.1). Windows fingerprint enrollment is
  now BROKEN (expected; recoverable via Windows re-enroll).
- **DONE (2026-07-24):** production capture-path RE (7-way `re` fanout). **PIVOTAL:
  `00bc` is a MATCH-ON-CHIP sensor** — Windows matches on-chip (Match-In-Sensor)
  and never pulls a raw image to the host. "proto-IOCTL 0x65/0x191" were actually
  host-side WBDI event ids (not wire ops); `vfmUtilCaptureImage` is the
  wake-on-finger path (no pixels); `FRAME_READ`/`FRAME_STREAM` are diagnostic-only
  (hence `0x0689`). See `docs/frame-capture-re.md` → "PRODUCTION CAPTURE-PATH RE".
- **DECIDED + RE'd (2026-07-24): pursue MOC (Match-In-Sensor).** The on-chip
  enroll/verify command spec is now reverse-engineered (3-way `mis*`/DB2 fanout):
  enroll = VCSFW `0x96` (QM struct sub-op; AddImage→60-byte stat; loop to
  progress==100); verify/identify = `0x99` `misIdentifyMatchCmd` (36-byte QM result;
  score > host threshold); templates persist as DB2 objects (type tag `0x20`) via
  `WRITE_OBJECT 0xa2`. **Corrected pydrv DB2 bug: `DB2_CLEANUP` is `0xa4` (pydrv
  wrongly aliases it to `0xa3`); `DB2_WRITE_OBJECT 0xa2` is missing.** Full spec:
  `docs/frame-capture-re.md` → "MOC COMMAND SPEC (2026-07-24)".
- **RESIDUAL RE DONE (2026-07-24):** exact QM/DB2 wire layouts pinned + two
  corrections — MOC enroll/verify do **NOT** arm `FRAME_ACQ`/`EVENT_CONFIG` (sensor
  captures on-chip on the `0x96`/`0x99` cmd); **SAP not needed** for DB2. See
  `docs/frame-capture-re.md` → "RESIDUAL RE RESOLVED" + updated "PHASE C PLAN".
- **WINDOWS CAPTURE DONE (2026-07-24): full enroll+verify recipe obtained.** Frida
  plaintext capture on an identical Windows tablet (`wincapture/`) gave ground truth.
  **Our enroll crash root cause: missing the `0x39` sensor/IPL-config command + wrong
  `FRAME_ACQ` (used 25B diagnostic; production is 17B `80 0c000000 01000000 01000008
  01010100`).** No SAP and no `0xa2`/pEncryptedTemplate exist in the flow — the
  template persists on-chip via the `0x96/3` commit; both prior "blockers" dissolved.
  Enroll = start(`0x96/1`) → per-image[`0x39`+`FRAME_ACQ(17B)`+finger wait →
  `add_image 0x96/2`→82B stat, progress@stat+2 to 100] → commit(`0x96/3`, TUID+userid)
  → end(`0x96/4`); verify = capture-arm + `0x99` identify (177B reply w/ matched TUID
  + score). Full byte templates: `docs/frame-capture-re.md` → "WINDOWS DYNAMIC CAPTURE".
- **NEXT — Phase D5 (implement + validate):** rework `pydrv` enroll/verify to the
  captured recipe (17B FRAME_ACQ + `0x39` config), validate on our sensor with finger
  presses. Open: whether the 4 static `0x39` bodies are Augusta-generic or per-sensor.
- **Binary RE:** use the local **`re`** subagent (`.opencode/agent/re.md`, Opus,
  gitignored). Both adapter DLLs (`synaFpAdapter103/104.dll`) + USB DLLs + r2 seed
  dumps are now staged in the sandbox `re-frameacq/`.

## Quick facts
- Working branch: **`00bc-dev`** (off `origin/rev`) — Path B development on the
  reverse-engineered Python driver (`pydrv/`), plus this doc + `docs/` +
  read-only probes in `pydrv/diag/`. Phase 0 confirmed `00bc` is a Tudor-protocol
  "Augusta" sensor at fw 10.1 (see the doc). Note: `rev` and the relink line
  (`relink`/`00bc`/`00bc-re`) are **unrelated git histories**. `00bc` is the
  *blind* relink port; `00bc-re` holds the Phase 0 docs on the relink line
  (bookmark); `upstream` = `Popax21/synaTudor`.
- The tablet is reachable over SSH as host `tablet`, now configured to log in as
  **root** (key-only). Agents may run diagnostics and installs there.
- Scope decision: pursue this **as far as needed, including full reverse
  engineering.**
- Windows USB-capture topology is **not yet decided**: the sensor is *internal*
  to the tablet, so a Mac-hosted VM cannot see it. Realistic options are a
  Windows VM *on the tablet* (qemu/kvm passthrough) or dual-booting the tablet.
  Deferred until/unless capture is needed.
- Safety net: a timeshift (btrfs) on-demand snapshot `2026-07-23_13-47-14`
  predates this work; scheduled snapshots are also active. `timeshift` is usable
  over the root SSH session if a manual restore point is wanted.

## Working agreement
- Phase 0 (protocol family) and 1a–1c are DONE: `00bc` is Tudor-protocol
  "Augusta" fw 10.1; we have paired + established TLS. `pair`/`init`/`info` and
  read/capture commands are fine to use (Linux already owns the sensor).
- **Still NEVER run** the OTP/permanent or destructive ops: `provision` (0xe),
  `take ownership ex2` (0x4f), `reset ownership` (0x10), firmware `update`,
  storage `format`, `poke` — these can re-provision/brick the sensor.
- Sensor recovery: a killed capture can leave a half-open TLS session (plaintext
  → `15 03 03…` alert) or a stuck state (GET_VERSION → `0x0315`); clear with a USB
  `dev.reset()` + ~20–30s idle wait. Pairing data: `/etc/tudor/<id>.pdata`.
- Never print secrets/keys/tokens in plaintext.
- **Do NOT use the `gh` CLI** in this repo: it is authenticated only against
  `github.toasttab.com` (enterprise) and will not work for this GitHub.com fork.
  Use plain `git` over HTTPS.
- We have **no push permission** to `origin` (`dmophir/synaTudor`); commits stay
  local unless told otherwise. Do not attempt to push.
