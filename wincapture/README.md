# Windows fingerprint capture (Synaptics 06cb:00bc, Dell Latitude 7210)

We're porting this sensor to Linux. It matches **on-chip**, and two parts of the
protocol can't be read from the driver binary alone (a secure-session handshake and
the template format). Running a normal Windows fingerprint **enroll** and **verify**
once, with a small Frida hook attached, captures exactly what we need — the plaintext
commands the driver sends to the sensor (before they're encrypted for USB).

**This is read-only instrumentation.** It only *logs* the commands the Windows driver
already sends; it does not change the sensor, your fingerprints, or Windows. When
you're done you can uninstall Frida and delete the files.

## What you need
- The Latitude 7210 running Windows, with the fingerprint reader working
  (Settings → Accounts → Sign-in options → Fingerprint recognition).
- Python 3 (https://python.org) — during install tick "Add python.exe to PATH".
- Frida: open an **Administrator** PowerShell/Command Prompt and run:
  ```
  pip install frida
  ```
- These two files (`syna_frida_capture.py`, this README) in a folder, e.g. `C:\syna\`.

## Steps
1. Open an **Administrator** terminal (right-click → "Run as administrator"). This is
   required so the hook can attach to the driver host process.
2. `cd C:\syna\` (wherever you put the files).
3. Start the capture:
   ```
   python syna_frida_capture.py
   ```
   Within a second or two you should see a line like:
   ```
   [..] PID=#### HOOKED mod=synaWudfBioUsb103.dll rva=0x8a570 ...
   ```
   If you instead see "no synaWudfBioUsb module", tell me — the driver may be named
   slightly differently and I'll adjust. **Leave this window running.**

   > Tip: if nothing hooks, unlock the fingerprint reader once (e.g. open the
   > Fingerprint settings page) so Windows loads the driver, then restart the script.

4. **Capture an ENROLL.** In Settings → Sign-in options → Fingerprint:
   - If a fingerprint is already set up, click **Remove** first.
   - Click **Set up** / **Add** and enroll a finger — do the full guided process
     (lift/press the sensor the many times it asks, until it says "All set").
   The capture window will scroll with `REQ op=.. / REP op=..` lines as you enroll.

5. **Capture a VERIFY.** Trigger a match with the finger you just enrolled:
   - Press **Win+L** to lock, then unlock with your fingerprint; **or**
   - On the Fingerprint settings page use any "verify"/"try it"/"improve
     recognition" option.
   A couple more `REQ/REP` lines should appear.

6. Go back to the capture window and press **Ctrl+C**. It prints
   `Saved capture to syna_capture.log`.

7. **Send me `syna_capture.log`.** Also handy (optional but useful):
   - The `path=...` shown on the HOOKED line (tells me the exact driver version), and
   - a copy of that driver DLL if easy (from that path, e.g.
     `C:\Windows\System32\drivers\UMDF\synaWudfBioUsb103.dll`).

That's it — one enroll + one verify is enough. Thank you!

## Notes / troubleshooting
- The log contains the sensor **command bytes** for enroll/verify. It does **not**
  contain a usable copy of your fingerprint (the actual biometric template is built
  and stored inside the sensor chip), but treat the file as you would any diagnostic
  log and only send it to me.
- If `pip install frida` fails, try `python -m pip install frida`.
- If attaching fails with a permissions error, make sure the terminal really is
  elevated (Administrator).
- Multiple `WUDFHost.exe` may exist; the script injects into all of them and only the
  one hosting the fingerprint driver will report `HOOKED`.
