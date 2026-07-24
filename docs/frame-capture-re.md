# Frame-capture protocol RE (Synaptics Tudor 104 / Augusta 103)

Durable reverse-engineering reference for the sensor's **image-capture** command
path (`FRAME_ACQ`/`FRAME_READ`/readiness), produced 2026-07-23 by an Opus
`re`-subagent fanout over the extracted Windows DLLs
(`synaWudfBioUsb104.dll` = Tudor, `synaWudfBioUsb103.dll` = Augusta/`06cb:00bc`).
This augments `rev/proto.txt` (which marked most of these fields `????`).

Companion to [`00bc-porting.md`](00bc-porting.md). All addresses are RVA-style as
reported by radare2 (`aaa`) on the extracted DLLs. Cross-checked 103≡104 unless
noted. **All multi-byte fields are little-endian** (the u16/u32 field helpers are
identity — see below).

> Bottom line still open: with `FRAME_ACQ` accepted and a frame latched,
> `FRAME_READ(seq=0)` still returns sensor status `0x0689`. Every byte/seq/
> readiness detail below matches the Windows driver, so the blocker is a
> capture-state/timing condition not visible in static RE. Next step is the
> on-device `pydrv/diag/frame_read_probe.py` seq-sweep.

## Function address cross-reference (104 → 103)
| Function | 104 (Tudor) | 103 (Augusta) | Notes |
|---|---|---|---|
| opcode/alloc (`fcn`) | `0x180087530` | (same role) | allocates buf, sets 1-byte opcode from `cx`; zero-inits buffer |
| generic sender | `0x180087000` | `0x18008a570` | 104 dispatches via `[sensor+0xc8]`, 103 via `[sensor+0xd8]` |
| cmd-name log switch | `0x180087600` | — | maps opcode→`VCSFW_CMD_*` string for "CMD SEND/REPLY" traces |
| `tudorCmdFrameAcq` | `0x180083e80` | `0x180087060` | **byte-identical construction** |
| `tudorCaptureStart` | `0x18007c500` | `0x18007e7d0` | same 3-way flags branch |
| `tudorCmdFrameRead` | `0x180083b10` | `0x180086160` | 103 higher-level sig/offsets; **wire bytes identical** |
| FRAME_READ opcode set | `0x180083ce1` | `0x180086ec1` | `mov cx,0x7f` |
| `tudorCaptureProcess` | `0x18007c8b0` | — | capture state machine |
| `tudorCaptureFrameReadyStatusGet` | `0x18007d4e0` | — | readiness via ioctl 0x6a |
| `tudorCaptureFrameRead` | `0x18007d8e0` | — | reads frame, parses flags |
| `tudorUsbProtoIoControl` | `0x180081f38` | — | proto-IOCTL dispatcher |
| `palUsbDriverIoControl` | `0x1800685b0` | — | driver-IOCTL dispatcher |
| INTERRUPT_DATA_GET core | `0x18006b910` | — | reads cached interrupt report |
| status→result mapper | `0x180088750` | `~0x18008bc41` | 103 is a superset table |
| u16 field helper | `0x1800baba0` | (same) | **identity** (no byteswap) |
| u32 field helper | `0x1800babc0` | (same) | **identity** |
| u16 reply-status helper | `0x1800babd0` | (same) | **identity** |

## Command build/send infrastructure
- Requests are built by per-command builders that call the **opcode/allocator**
  `fcn.180087530` (allocates a zero-inited buffer of the given size, writes the
  1-byte opcode at offset 0), fill fields, then call the **generic sender**
  `fcn.180087000` (args: sensor, opcode in `edx`, req-size ptr, resp-size ptr).
- The sender reads the reply's first u16 as the **status** (104 @ `0x180087417`
  `movzx ecx,word[rax]` → helper `fcn.1800babd0`), then maps it (below).
- **Endian helpers `fcn.1800baba0`(u16)/`fcn.1800babc0`(u32)/`fcn.1800babd0`** are
  pure `mov`/`movzx`+`ret` — **identity**, i.e. host little-endian on the wire.
  Confirms `rev/proto.txt` "all integers little endian".

## FRAME_ACQ (0x80) — `tudorCmdFrameAcq` (104 `fcn.180083e80`)
Multi-mode, record-based, little-endian. **Mode selector = arg3 (1/2/3)** chosen
by the caller `tudorCaptureStart` (`fcn.18007c500`) from `capture_flags`:

| condition | mode | num_frames | size |
|---|---|---|---|
| `(flags&1)==0` | 1 | arg5 | 17 B |
| `(flags&1) && (flags&2)==0` | 2 | 1 | 17 B |
| `(flags&1) && (flags&2)` | 3 | (var_40h=1) | 25 B |

- `arg4` byte = `(other & 1)`; `rev/rev.txt` says a normal enroll uses "other=1",
  "num_frames=1", "capture flags 7 or 15". Flags 7/15 both have bits 0&1 set →
  **mode 3** by the branch above. (One subagent argued the vfm layer re-derives
  the flags to select mode 2; the 4/12→7/15 transform lives in the external
  `synaFpAdapter/vfm` module, not in this DLL, so it wasn't single-stepped.
  **Empirically both modes are ACCEPTED and neither fixes `FRAME_READ`.**)

Exact bytes (verified against the builder + `proto.txt` "always" fields):
```
mode 3 (25B, num_frames=N):
  80 | 01000000 | <N:u32> | 0100 00 08 | 01 <arg4> 00 00 | 0100 00 0c | 1400 02 00
  offsets: [0]=80 [1-4]=flags(=1) [5-8]=N [9-A]=1 [B]=0 [C]=8 [D]=1 [E]=arg4
           [F]=0 [10]=0 [11-12]=1 [13]=0 [14]=0x0c [15-16]=0x14 [17]=2 [18]=0
  for N=1:  80 01000000 01000000 0100 00 08 01 01 00 00 0100 00 0c 1400 02 00
mode 2 (17B): 80 00000000 <N:u32> 0100 00 08 01 01 01 00
mode 1 (17B): 80 00000000 <N:u32> 0100 00 08 00 01 00 00
```
Key builder addresses: `sensor+0x90` seq reset to 0 @ `0x180083f6c`; num_frames
(arg_c0h) → payload+4 @ `0x180083fff`; flags(arg2) → payload+0 @ `0x180084013`;
`(arg2&2)` short-circuits records @ `0x18008401f`; base size 8 (+8 if mode3, +9)
@ `0x180083f8b..`; alloc `mov cx,0x80` @ `0x180083fcc`; send `mov edx,0x80` @
`0x18008416e`. Size math: `var_30h`=8, +8 iff mode3, +9 → 17 or 25.

## FRAME_READ (0x7f) — `tudorCmdFrameRead` (104 `fcn.180083b10`)
9-byte request, **matches pydrv exactly**:
```
[0]=0x7f  [1-2]=seq(u16)  [3-4]=0  [5-6]=0xffff (max size)  [7-8]=3
```
- **seq source = `sensor+0x90`**: reset to 0 by `FRAME_ACQ`; read into the req @
  `0x180083d19` (`movzx ecx,word[rax+0x90]`); **incremented ONLY after a fully
  successful read** @ `0x180083e17-0x180083e29` (downstream of the success check).
  ⇒ **first read is seq=0**. The three writers of `sensor+0x90` (`0x180083e29`
  read-inc, `0x180083f6c` ACQ-reset, `0x180085bf6` another cmd's post-success inc)
  **never sync it to the interrupt frame index**. So seq ≠ frame index.
- Response parse (`tudorCaptureFrameRead` `fcn.18007d8e0`): `frame_flags & 2` →
  finger-lifted (`session+0x38`); `& 1` → last-frame (`session+0x3c`); if
  want-last && !last → returns `0xca` + WPP "The last frame is not received".

## Readiness poll — proto-IOCTL 0x6a = cached interrupt read
`tudorCaptureFrameReadyStatusGet` (`fcn.18007d4e0`) calls `[sensor+0xc8](dev,
0x6a, 0, 0, &buf3)` (dst 3 bytes).
- Dispatcher `tudorUsbProtoIoControl` (`fcn.180081f38`), opcode decode @
  `0x18008203a` (`dec eax; cmp 0x69; ja default`), jump tables @ `0x180082928`
  (byte index) / `0x180082908` (dword offsets). Opcodes:
  - `0x65` DEVICE_INFO (GET_VID_PID), `0x66` GET_TLS_STATE, `0x67` SEND_CMD_DATA
    (the normal command channel), `0x68` DEVICE_RESET, `0x69` WRITE_DFT,
    **`0x6a`** case @ `0x1800820cb`, default → "Unknown Request" (returns 0x71).
- `0x6a` case: requires dst≥3; calls `palUsbDriverIoControl` (`fcn.1800685b0`,
  table @ `0x180068cf0`) with **driver-IOCTL 3 = VCSDRV_IOCTL_INTERRUPT_DATA_GET**
  (handler `0x18006878e`), 7-byte dst; then **repacks 7→3**: `out[0]=intr[0]`,
  `out[1]=intr[5]`, `out[2]=intr[2]` (@ `0x180082176/0x1800821a2/0x1800821ce`).
- INTERRUPT_DATA_GET core (`fcn.18006b910`) does **no fresh USB transfer**: it
  returns the **cached 7-byte interrupt report** from `[handle+0x90]` (count at
  `[handle+0x8c]`); a background WinUSB thread (`palUsbDriverThreadFunc`)
  continuously reads EP `0x83` into that cache.
- ⇒ **ioctl 0x6a is equivalent to pydrv's `get_event_data()` reading EP 0x83.**
- Readiness math: `out[1]` (=interrupt byte5, frame index &0x7) vs `sensor+0x69`
  (ref, reset 0) → "index changed" bit; `out[0]` (=interrupt byte0, state) `==2`
  → "latched" bit. Observed transition on our sensor: `01000000000001` →
  `02000000000101` (byte0 1→2, byte5 0→1) = both bits set = ready.

## Capture sequence (state machine `tudorCaptureProcess` `fcn.18007c8b0`)
1. `tudorClearCaptureContext` (`fcn.18007dfd0`) — free buffers (no USB).
2. Set flags only: `sensor+0xb4=1` (in-capture), `sensor+0x69=0`, `sensor+0x90=0`.
3. **FRAME_ACQ (0x80)** (arms capture; via proto 0x67 SEND_CMD_DATA).
4. Poll readiness (proto 0x6a = cached interrupt) until latched. No new bus cmd.
5. **FRAME_READ (0x7f)**; on success post-process (IPL) + append; loop until
   last-frame flag. **No `FRAME_FINISH (0x81)` is sent in the loop** — searched
   both DLLs, the 0x81 opcode is never fed to the allocator. Termination is
   flag-driven; cleanup via event-config/reset paths.

### 104-only: SET_POWER_POLICY before FRAME_READ (NOT a wire transfer)
In the 104 sender `fcn.180087000`, when `sensor+0x19 (vid_pid cap) == 1` AND
opcode `== 0x7f`, it first issues proto-IOCTL `0x12` = SET_POWER_POLICY →
`WinUsb_SetPipePolicy(PIPE_TRANSFER_TIMEOUT = 0x1388 = 5000ms)` on interrupt pipe
`0x83` (`0x1800871ea`: pattern `c744246883000000 c744246c88130000`). This is a
**host-side WinUSB pipe config, not a USB bus transaction**, and is **absent in
103** (`06cb:00bc`). `sensor+0x19` comes from the GET_VID_PID init IOCTL (0x65).
Do NOT reproduce this as a wire transfer on Linux.

## Status-code mapping (`fcn.180088750` in 104)
Sensor firmware status (reply u16) → driver result. Success = `{0x000, 0x412,
0x5cc}` → 0. Known mappings:
`0x401→0xd1, 0x404→0x68, 0x405-0x406→0x6f, 0x509→0x12e, 0x5b6→0xda, 0x6e0→0xdc,
0x6ea→0xdd`. **Default (anything unmapped, incl. `0x0689`) → `0xca`** + WPP
"FW command reply failed with status= %d:". 103 mapper is a **superset**
(also handles `0x680`, `0x5cb`; extra results `0x1f5/0xdf/0x136/0xdd`); `0x0689`
is unmapped in both → `0xca`.

### 0x0689 analysis
`0x0689` is a **raw sensor firmware status** in the `0x6xx` "sensor" band (same
band as `0x6e0/0x6ea = VCS_RESULT_SENSOR_*`). No symbolic name exists in the DLL;
it surfaces raw. Related capture strings in the DLL:
`VCS_RESULT_SENSOR_FRAME_NOT_READY`, `VCS_RESULT_SENSOR_CAPTURE_RESET`,
`"Sensor is in capture state"`, `"The frame is not ready (status=%d)"`. Best
interpretation: **sensor rejecting `FRAME_READ` as a capture-state/not-ready
condition** — consistent with an incomplete/mis-ordered capture, though the exact
firmware precondition lives in sensor firmware, not the DLL. Confidence: medium.

## What this rules out for the pydrv 0x0689 blocker
- Not a missing inter-command bus transfer (0x6a = cached interrupt read; pydrv
  already reads EP 0x83).
- Not a wrong `FRAME_READ` seq (first read is seq=0 by design).
- Not malformed `FRAME_READ` bytes (identical to the driver).
- Not the `FRAME_ACQ` mode (both 17B/mode-2 and 25B/mode-3 are accepted on device
  and both still yield `FRAME_READ → 0x0689`).
- Readiness gate (`interrupt[0]==2` && index changed) was satisfied at read time.
⇒ Remaining candidate = a capture-state/timing condition; resolve on-device
(`frame_read_probe.py` seq-sweep) or via Windows dynamic capture (Frida; frame
cmds are TLS-encrypted so passive USBPcap won't reveal plaintext).

## Uncertainties / open items
- Exact `capture_flags`→mode transform (in the external vfm module) not traced;
  mitigated because both modes are accepted empirically.
- Whether `06cb:00bc` has `sensor+0x19 (vid_pid cap) == 1` (affects only the
  104-style SET_POWER_POLICY, which is host-side anyway).
- Precise firmware meaning of `0x0689` (sensor-side; not in DLL).

## Appendix — pairing / HS-key RE landmarks (from 1b.6, main-session RE)
Kept here so the function addresses aren't lost; the semantics + reversibility
analysis are in [`00bc-porting.md`](00bc-porting.md).
- **HS (host-signing) key is DERIVED, not stored.** Chain:
  `palGenHSPrivKey` → `palSymKeyGen` → `palPRF`.
  - `palGenHSPrivKey`: 103 `fcn.1800724d0`, 104 `fcn.1800bc7f0` (found via the
    `HS_KEY_PAIR_GEN` string, 104 xref `lea` @ `0x1800bcbee`). Builds a **32-byte
    seed inline** via byte-`mov`s (offsets ~0x88..0xa7 on the stack).
  - `palSymKeyGen`: 103 `fcn.1800779f0`. `palPRF`: 103 `fcn.1800743b0`, which calls
    **`BCryptDeriveKey` with `TLS_PRF` + `SHA256`** ⇒ the derivation is the
    **TLS 1.2 PRF**. Output 32 bytes = the ECC private scalar.
  - **All three functions are byte-identical between 103 and 104** (normalized
    disasm diff = 0) ⇒ the derived HS key is identical across generations.
- **HS seed (identical 103≡104):**
  `b3494469 d36e4861 9f0b2c7b d3920374 9f0371df 1f2ea374 2b7b05bb 4daee823`.
  Derived HS private scalar = pydrv's bundled `hskey.pem`
  (`e8a2a2b6 656254d6 acb0ef47 9cae4140 c7e8e260 db3f642e 35d4099c 01b36a86`).
  ⇒ **pydrv's `hskey.pem` is correct for Augusta; no swap needed.**
- **Red herring:** `rev.txt`'s `palSynaKmGet` constant
  `717cd72d0962bc4a2846138dbb2c24192512a76407065f383846139d4bec2033` is NOT the
  HS-key input (absent in the 103 DLL); the real input is the `b34944…` seed above.
- **Sensor public keys embedded in `synaWudfBioUsb103.dll`** (little-endian):
  `10.1` x@`0x130de3` y@`0x130e27`; `10.1-kf` x@`0x130ee6` y@`0x130f2a`. These
  match pydrv `sensor_keys/10.1.tsk` / `10.1-kf.tsk` ⇒ device-cert verification
  works. (Our sensor: fw 10.1, key_flag set ⇒ uses `10.1-kf`.)
- **Cert / pairing wire format** (from `pydrv/tudor/sensor/pair.py`, confirmed on
  device): `SensorCertificate` = **400 bytes** — magic `0x5f3f`, curve `23`
  (SECP256R1), pubkey X/Y as 68-byte LE fields, `cert_type`, `sign_size`,
  256-byte signature (ECDSA-SHA256, signed by the HS key). `PAIR (0x93)` request
  = opcode + 400-byte host cert; response = `0x322` bytes = status(2) +
  host cert(400) + device cert(400). Pairing data blob = privkey(0x44) +
  host cert(400) + sensor cert(400) = 868 bytes.
