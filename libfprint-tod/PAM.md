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

## Enable for graphical/console login
Add the same `auth sufficient pam_fprintd.so` line near the top of the `auth` section of
the relevant service (e.g. `/etc/pam.d/system-local-login` for console, or your display
manager's PAM file such as `/etc/pam.d/gdm-password` / `sddm`). Editing `system-auth`
directly enables it everywhere but is higher risk; prefer per-service files.

## Notes
- Match-on-chip: the sensor decides match/no-match; a poor press yields no-match (retry).
- If a session is interrupted the sensor can wedge (a plaintext `15 03 03…` TLS alert to
  GET_VERSION); it self-clears with a USB reset + ~30s idle. fprintd falls back to password
  meanwhile.
