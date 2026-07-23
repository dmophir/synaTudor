# Agent onboarding

This is a fork of `Popax21/synaTudor` being used to bring the Synaptics
`06cb:00bc` fingerprint sensor (Dell Latitude 7210 2-in-1) up on Linux.

**Before doing anything, read [`docs/00bc-porting.md`](docs/00bc-porting.md).**
It is the source of truth for prior art, the repo/branch layout, the pivotal
unknowns, the decisions on effort/scope, and the phased strategy. Keep it
up to date — append Phase 0 diagnostic results and any decisions there as work
proceeds.

## Quick facts
- Working branch: `00bc-re` (research/enablement work + this doc). `00bc` is the
  *blind*, unverified port from `00be`; `relink` is the DLL-relinking base; `rev`
  is the reverse-engineering effort (protocol docs + Python prototype driver);
  `upstream` = `Popax21/synaTudor`.
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
- Diagnose the sensor's protocol family (Phase 0) before committing to a driver
  strategy; do not build further on the unverified `00bc` branch until the Dell
  driver's `.inf` and an on-device probe confirm the family.
- Keep **sensor interactions read-only during diagnosis**: pydrv `info` only.
  Never run `pair`, `init` (with pairing), `provision`, `update`, storage
  `format`, `poke`, or `reset ownership` — these can re-own/rekey or brick the
  sensor and would break the existing Windows enrollment.
- Never print secrets/keys/tokens in plaintext.
- **Do NOT use the `gh` CLI** in this repo: it is authenticated only against
  `github.toasttab.com` (enterprise) and will not work for this GitHub.com fork.
  Use plain `git` over HTTPS.
- We have **no push permission** to `origin` (`dmophir/synaTudor`); commits stay
  local unless told otherwise. Do not attempt to push.
