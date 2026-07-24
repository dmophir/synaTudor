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
- **OPEN PROBLEM:** image capture. Raw `FRAME_ACQ`/`FRAME_READ` is a dead end
  (returns `0x0689` even fully armed — it's a diagnostic/IPL-gated path).
  **Next:** the production capture path (proto-IOCTL `0x65`/`0x191` + finger-detect
  + host-side matching). See the "Next-session handoff" in `docs/00bc-porting.md`.
- **Binary RE:** use the local **`re`** subagent (`.opencode/agent/re.md`, Opus,
  gitignored) — binary-only by default; stage DLLs per the handoff (esp.
  `synaFpAdapter103.dll`, not yet staged).

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
