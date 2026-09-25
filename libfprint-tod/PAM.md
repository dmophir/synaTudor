# PAM integration (fingerprint login/sudo)

`pam_fprintd.so` (from the `fprintd` package) bridges PAM to the fingerprint device via
the libfprint TOD driver installed by this project. Enroll a finger first:

```sh
fprintd-enroll        # press the finger ~8 times
fprintd-verify        # confirm it matches
```

## Enable for `sudo` (recommended first test)
Add `pam_fprintd` as a *sufficient* auth method **before** the password stack, so a
successful fingerprint authenticates and a failed/absent one falls back to the password
(no lockout risk). Keep a root shell open while testing, just in case.

Desired `/etc/pam.d/sudo`:
```
#%PAM-1.0
auth		sufficient	pam_fprintd.so
auth		include		system-auth
account		include		system-auth
session		include		system-auth
session		optional	pam_systemd.so class=none
```

Apply safely (with backup):
```sh
sudo cp /etc/pam.d/sudo /etc/pam.d/sudo.bak.tudor
sudo tee /etc/pam.d/sudo >/dev/null <<'EOF'
#%PAM-1.0
auth		sufficient	pam_fprintd.so
auth		include		system-auth
account		include		system-auth
session		include		system-auth
session		optional	pam_systemd.so class=none
EOF
```
Test in a NEW terminal: `sudo -k; sudo true` → it should prompt
"Place your finger on the fingerprint reader"; on a match, no password is asked.
Revert with: `sudo cp /etc/pam.d/sudo.bak.tudor /etc/pam.d/sudo`.

## Graphical login / lock screen (GNOME / GDM) — no config needed
GNOME/GDM ship a dedicated fingerprint PAM service, `/etc/pam.d/gdm-fingerprint`, which
already contains `auth required pam_fprintd.so`. GDM invokes it as a *separate* auth path
from `gdm-password`, so once a finger is enrolled (`fprintd-enroll`, or GNOME Settings →
Users → Fingerprint Login) the greeter **and** the lock screen offer fingerprint unlock
with **no PAM edits**. Do **not** add `pam_fprintd` to `gdm-password` — the password path
stays untouched (no lockout risk), and GDM handles the two paths itself.

Verify: lock with Super+L, present an enrolled finger → it unlocks. A non-enrolled finger
falls back to the password field. Tested working on GDM 50 / GNOME Shell 50 with this
driver on `06cb:00bc`.

Press behaviour (important): the GNOME lock screen fires up to **three** identify attempts
and then falls back to password. The driver debounces a held/already-present finger (see
`pydrv/tudor/sensor/moc.py` `capture_one_frame`): if you keep the finger down it will not
re-capture the same static frame — **lift and re-press** for each attempt. Present the
finger deliberately (firm, centered); a poor/partial press is a legitimate no-match.

## Console / TTY login (getty) — optional
Text-console logins go through `/etc/pam.d/login`. To allow fingerprint there, add
`auth sufficient pam_fprintd.so` **after** the `pam_nologin` line (so a nologin lock is
still enforced and the password remains the fallback):
```
#%PAM-1.0

auth       requisite    pam_nologin.so
auth       sufficient   pam_fprintd.so
auth       include      system-local-login
account    include      system-local-login
session    include      system-local-login
password   include      system-local-login
```
Back up first (`cp /etc/pam.d/login /etc/pam.d/login.bak.tudor`), test on a spare VT
(Ctrl+Alt+F3) with your GUI session still open, and keep a root shell handy.

- Prefer editing `login` over `system-local-login`: the latter is `include`d by
  `gdm-password`, so editing it would also pull fingerprint into GDM's password path.
- **Known TTY quirk:** while `pam_fprintd` waits for a finger the console is *not* in
  password-read mode, so anything you type echoes in **cleartext** and is **not** accepted
  as the password. The (echo-off) password prompt only appears **after** the fingerprint
  attempts are exhausted. This is inherent to `pam_fprintd` on a text console (the
  graphical greeter/lock screen accept fingerprint and typed password in parallel and are
  unaffected). If that trade-off is unwanted, revert `login` to password-only.

## Notes
- Match-on-chip: the sensor decides match/no-match; a poor press yields no-match (retry).
- If a session is interrupted the sensor can wedge (a plaintext `15 03 03…` TLS alert to
  GET_VERSION); it self-clears with a USB reset + ~30s idle. fprintd falls back to password
  meanwhile.
