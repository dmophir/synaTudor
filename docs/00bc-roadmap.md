# 00bc roadmap — outstanding work

Post-`(c)` follow-ups for the Synaptics `06cb:00bc` MOC driver. The core goal is **done**
(match-on-chip enroll/verify/identify/delete via `fprintd` + PAM `sudo` login, commit
`5474142`). Everything below is polish / hardening / untested paths. Each item is scoped to
be tackled in its **own session** (sessions run long). Ordered roughly by value ÷ effort.

Conventions for every item: read [`AGENTS.md`](../AGENTS.md) +
[`docs/00bc-porting.md`](00bc-porting.md) → "libfprint MOC DRIVER (2026-09-24)" first. The
driver lives in `libfprint-tod/`; rebuild with `ninja -C libfprint-tod/build`; reinstall
with `sudo bash libfprint-tod/install-dev.sh` (restages pydrv + `.so` + restarts fprintd).
Isolated (no-fprintd, no-sudo) testing: `libfprint-tod/tools/moc_selftest.c` built with
`gcc … $(pkg-config --cflags --libs libfprint-2)` and run with
`FP_TOD_DRIVERS_DIR=…/build TUDOR_PYDRV_PATH=…/pydrv`. Finger presses are done by the human
during a ~25–30 s blind window (the tool buffers output — coordinate a "GO"). Never run the
destructive ops (provision `0xe`, take-ownership `0x4f`, reset-ownership `0x10`, fw update,
FORMAT `0x3f`/`0xa5`, poke `0x8`). A killed capture can wedge the sensor (GET_VERSION →
`0x0315` or a `15 03 03…` TLS alert) → USB `dev.reset()` + ~30 s idle to recover.

---

## A. Functional validation gaps (highest value, low effort)

### A1. Validate `fprintd-delete` end-to-end — DONE (2026-09-24)
- **Why:** the `dev_delete` vfunc → `pyembed_delete_template` → user-keyed
  `SensorDB2.delete_template` path was only exercised via the harness / raw pydrv this
  session, not through `fprintd-delete`.
- **Do:** enroll a finger, then `fprintd-delete dylan`; confirm the DB2 template+user are
  gone (`moc_selftest list` → 0) and fprintd no longer lists the finger.
- **Files:** `libfprint-tod/src/device.c` (`dev_delete`, `idle_delete_done`),
  `src/pyembed.c` wrapper `delete_template`.
- **Watch:** the print handed to `dev_delete` must carry the 16-byte user key in fpi-data
  (it does, from enroll). Effort: ~15 min + a few presses.
- **RESULT (PASS):** deleted a print that had been serialized to disk in a *prior* session
  (stronger than a same-session enroll→delete). All three views agreed: `fprintd-list` →
  none; `moc_selftest list` → 0; on-chip `DB2Info` current user/template/payload all → 0
  (deleted-counts +1). Parent-user object pruned (no orphan slot). Re-enrolled to restore.
  Ran fully as `dylan` (no `sudo`) via the per-user pdata copy. Details: porting log
  "A1: `fprintd-delete` validated end-to-end". Also fixed two stale comments inline while
  here (harness `print_tuid` + `tudor-moc.h` fpi-data description now match the key-only
  `ay` format).

### A2. Multi-finger 1:N identify — DONE (2026-09-25)
- **Why:** the gallery→user resolution (`verify_once` with N user keys, matched template →
  parent user) is implemented but only tested with a single enrolled template.
- **Do:** enroll two different fingers (two fprintd prints / two DB2 users), then verify each
  and confirm each resolves to the correct print; also confirm an un-enrolled finger →
  no-match. Optionally use `moc_selftest identify-loop`.
- **Files:** `src/pyembed.c` (`verify_once`, `_templates_by_user`), `src/device.c`
  (`idle_verify_done` gallery match, `collect_target_tuids`).
- **Watch:** DB2 slot pressure if many enroll/delete cycles (see C1). Effort: ~30 min.
- **RESULT (PASS + bug fix):** enrolled a 2nd finger (right-middle) → two DB2 users U1/U2;
  1:N `identify-onchip` resolved finger#1→U1 and finger#2→U2 (distinct, correct, no
  cross-match); `fprintd-verify -f` match/no-match confirmed the per-slot restriction
  end-to-end. **Found + fixed a real bug:** an un-enrolled finger made the matcher return
  `0x050b` (a no-match code distinct from `0x0509`) which `identify()` treated as a fatal
  error → device error mid-auth. `moc.py` now maps `0x050b` to a clean no-match
  (`MATCHER_NO_MATCH_STATUSES`); restaged so fprintd/PAM get it. 2nd enroll reclaimed a
  tombstone slot (no exhaustion). Details: porting log "A2: multi-finger 1:N identify".

### A3. Console / display-manager login PAM — DONE (2026-09-25)
- **Why:** only `sudo` is wired + tested. Real login is the headline use case.
- **Do:** add `auth sufficient pam_fprintd.so` near the top of the `auth` stack of the
  target service — `/etc/pam.d/system-local-login` (getty/console) and/or the DM
  (`gdm-password`, `sddm`, …). Prefer per-service files over editing `system-auth`
  globally. Keep a root shell open; test then revert if needed.
- **Files:** system PAM (not in-repo); document in `libfprint-tod/PAM.md`.
- **Watch:** don't lock yourself out; `sufficient` + password fallback is safe. Note the
  fprintd/logind interaction on the greeter. Effort: ~30 min.
- **RESULT (DONE + real fix):** GDM/GNOME graphical login needed **no** PAM edit —
  `/etc/pam.d/gdm-fingerprint` already wires `pam_fprintd` and GDM runs it as its own path.
  Testing exposed the real blocker: the GNOME lock screen fires **3 identify attempts in
  ~1.5s** and our driver re-captured the *still-present static finger* on each rapid re-arm
  → stale no-match ×3 → password ("rapid fail-out"). **Fixed** with a debounce in
  `pydrv/tudor/sensor/moc.py` `capture_one_frame` (a press within 0.4s of arming ⇒ finger
  already down ⇒ wait for lift + fresh press). Validated: lock screen now unlocks via
  fingerprint (verify-match, scores 0x595/0x6a2). Console/TTY enabled via `/etc/pam.d/login`
  (`sufficient` + password fallback); documented the inherent pam_fprintd/TTY cleartext
  quirk. Details: porting log "A3: graphical + console login PAM". New read-only diag:
  `diag/finger_present_probe.py`. Follow-up candidates: tune debounce thresholds; a proper
  finger-present/level detection would also fix a finger held from before arming (edge-only
  today).

### A4. Reboot persistence + autoload
- **Why:** confirm an enrolled finger survives a reboot with no manual steps.
- **Do:** enroll, reboot, `fprintd-verify` and `sudo` fingerprint without re-enroll. Confirm
  the udev rule (uaccess + driver load) and pydrv stage under `/usr/lib` persist, on-chip
  template persists, and fprintd DB (`/var/lib/fprint/dylan`) persists.
- **Watch:** if the sensor comes up wedged post-boot, the `open` self-heal should recover.
  Effort: ~15 min + a reboot.

---

## B. Robustness / hardening

### B1. suspend/resume across a real system suspend
- **Why:** `dev_suspend`/`dev_resume` are currently no-ops (`fpi_device_*_complete(NULL)`).
  A real suspend likely resets the sensor / drops the TLS session.
- **Do:** enroll, `systemctl suspend`, resume, then `fprintd-verify`. If it fails, decide
  the model: either (a) tell libfprint we can't suspend (complete suspend with an error so
  it closes/reopens around suspend), or (b) detect a dead session on the next op and
  reopen. Reference `relink:libfprint-tod/src/suspend.c` for the sleep-inhibitor pattern.
- **Files:** `src/device.c` (`dev_suspend`/`dev_resume`), possibly `pyembed`/wrapper for a
  liveness check.
- **Watch:** interaction with the `open` self-heal; don't double-reset. Effort: ~1–2 h.

### B2. Gentler close / open-close stress test
- **Why:** `USBCommunication.close()` does a full USB `dev.reset()` on every close; rapid
  fprintd open→op→close cycles could still wedge (a wedge was seen once this session).
- **Do:** stress loop of open/verify/close (via `moc_selftest` in a shell loop, or repeated
  `fprintd-verify`); if wedges recur, consider skipping the reset on a clean close (just
  release the interface + TLS close_notify) and/or keeping the device open across ops.
- **Files:** `pydrv/tudor/comm.py` (`USBCommunication.close`), wrapper `close_device`,
  `src/device.c` open/close. The `open` self-heal already retries on a wedge.
- **Watch:** don't regress the clean-teardown that pairing/CLI rely on — consider a
  driver-only "soft close" flag rather than changing pydrv defaults. Effort: ~1–2 h.

### B3. Enroll no-finger timeout → retry (not hard error)
- **Why:** `verify` maps a capture timeout to `FP_DEVICE_RETRY` (good); `enroll` still
  aborts with `FP_DEVICE_ERROR_GENERAL` on a 30 s no-finger.
- **Do:** in `enroll_worker`, on `code==0` report a retry via
  `fpi_device_enroll_progress(dev, stage, NULL, retry_error)` and continue the loop instead
  of failing (bounded by the 25-image cap).
- **Files:** `src/device.c` (`enroll_worker`). Effort: ~30 min.

### B4. Expose a match score threshold
- **Why:** `TUDOR_MOC_SCORE_THRESHOLD` is compile-time `0` (trust firmware). May want a
  host-side floor / config.
- **Do:** make it a meson option and/or `$TUDOR_MOC_SCORE_MIN` env read at open; gate
  `host_ok` in `idle_verify_done`. Decide a sane default from observed scores
  (~0x635–0xa46 matches seen). Effort: ~30 min.

---

## C. DB2 housekeeping

### C1. `DB2_CLEANUP 0xa4` (reclaim deleted-template slots)
- **Why:** each enroll/adaptive-update/delete leaves tombstones; DB2 shows
  `templates=<cur>/<deleted>/0` (0 avail). Hasn't blocked enroll yet, but could after enough
  cycles. Wire format is **not** RE'd (pydrv only defines the opcode).
- **Do:** RE the `0xa4` request/response (radare2 on the adapter DLLs, staged on the Mac;
  see AGENTS.md re-frameacq / `re` subagent) — likely body = category + pad (mirror
  `0x9f/0xa0/0xa3`). Add `SensorDB2.cleanup()` and call it after deletes / on open when
  `avail==0`. Validate `num_deleted_templates` drops and `avail` rises. **Never** confuse
  with FORMAT `0xa5`.
- **Files:** `pydrv/tudor/sensor/db2.py`, wrapper `delete_template`/`clear`.
- **Watch:** destructive-adjacent; test on the throwaway test enrollment only. Effort: ~2–4 h
  (RE-heavy).

### C2. Prune empty DB2 user slots in `clear_storage`
- **Why:** `clear_storage` deletes templates (and `delete_template` prunes a user once its
  last template goes), but users that already have **zero** templates linger (orphans like
  the `c8952e…` seen this session), consuming user slots.
- **Do:** in the wrapper clear path, after deleting per-user templates, enumerate all users
  and `delete_object(DB2_CAT_USER, uid)` for any with no templates.
- **Files:** `src/pyembed.c` wrapper (`delete_template`/a new `clear_all`), `src/device.c`
  `clear_worker`. Effort: ~30 min.

---

## D. Packaging / housekeeping

### D1. Properly package pydrv (drop the `/usr/lib/tudor-moc` copy)
- **Why:** `install-dev.sh` copies the `tudor` package to `/usr/lib/tudor-moc/pydrv` because
  fprintd runs `ProtectHome=true`. `pydrv/setup.py` doesn't declare subpackages and pulls
  `matplotlib`.
- **Do:** fix `setup.py` (`find_packages()` for `tudor`, `tudor.sensor`, `tudor.driver`,
  `tudor.driver.drvcmd`, `tudor.tls`, `tudor.win`; `package_data` for `*.tsk`/`hskey.pem`/
  `*.tupd`; make matplotlib optional/lazy) and either `pip install` to a system path or ship
  a PKGBUILD. Point the module's `pydrv_path` at the installed location.
- **Files:** `pydrv/setup.py`, `libfprint-tod/install-dev.sh`, `meson_options.txt`.
  Effort: ~1–2 h.

### D2. `--pid 0x00bc` default in `tudor.driver`
- **Why:** `pydrv/tudor/driver/__main__.py` still defaults `--pid` to `0x00be`.
- **Do:** default to `0x00bc` (or auto-detect among known Augusta PIDs). Effort: ~10 min.

### D3. Remove `prompt.md` cruft
- Untracked session-prompt file left in the repo root; delete or ignore. Effort: trivial.

---

## E. Nice-to-have

- **E1. Native C reimplementation** of TLS 1.2 + MOC to drop the embedded-CPython/pydrv
  dependency (big effort; only if the embed proves fragile in the field).
- **E2. Out-of-process host** (à la `relink` `tudor-host`) for privilege separation / crash
  isolation instead of embedding CPython directly in fprintd.
- **E3. finger metadata in `list` prints** — currently `list` prints omit the finger index
  (fpi-data is key-only by design); cosmetic in some fprintd UIs.
