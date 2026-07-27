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

## INDEPENDENT 103-BINARY RE-VALIDATION (2026-07-23) — no docs/rev.txt used
Three `re` subagents re-derived findings from the DLLs alone (binary only), to
guard against `rev.txt` being wrong for this device. Results:

### Chunk 1 — FRAME_ACQ: CONFIRMED against 103
- 103 addrs: builder **`fcn.180087060`**, caller `tudorCaptureStart` **`fcn.18007e7d0`**,
  opcode-alloc `fcn.18008a9a0`, sender `fcn.18008a570`, u16/u32 field writers
  `fcn.1800b6360`/`fcn.1800b6380` (both **identity/LE**).
- Multi-mode (arg3=1/2/3) via caller's flags branch (`&1`,`&2`) CONFIRMED; sizes
  17/17/25 CONFIRMED; num_frames u32 @[5-8], flags u32 @[1-4] CONFIRMED; mode-3 &
  mode-2 exact bytes CONFIRMED byte-identical to this doc; **103≡104**.
- New: FRAME_ACQ send has a **retry-on-status-`0xdf`(busy) loop, capped 3 tries**
  (`0x180087330-84`). Nuance: mode-3's num_frames is caller-supplied (arg5), only
  mode-2 forces num=1. Real enroll flags/arg5 unverified (caller reached via vtable).

### Chunk 3 — 0x0689 + capture architecture: BREAKTHROUGH
Status mapper **103 `fcn.18008bc30`** / **104 `fcn.180088750`** (logs "FW command
reply failed with status= %d:"). Success = {0x000,0x412,0x5cc}. Selected map
(VCS_RESULT_*; GEN_BASE=100, SENSOR_BASE=200):
`0x401→SENSOR_BAD_CMD(0xd1), 0x404→GEN_OPERATION_DENIED(0x68), 0x405/6→GEN_BAD_PARAM(0x6f),
0x509→MATCHER_MATCH_FAILED(0x12e), 0x5b6→SENSOR_FRAME_NOT_READY(0xda),
0x6e0→SENSOR_CALIBRATION_FAIL(0xdc), 0x6ea→SENSOR_CAPTURE_RESET, default→SENSOR_MALFUNCTIONED(0xca)`.
- **`0x0689` is UNMAPPED → default `0xca` = `VCS_RESULT_SENSOR_MALFUNCTIONED`.** The
  firmware deliberately returns MALFUNCTIONED (illegal-op-in-state), **not** the
  benign `0x5b6` "frame not ready". ⇒ our `FRAME_READ` is being rejected as an
  illegal operation for the current sensor state.
- **This is an image-off-sensor, HOST-matched design (NOT on-chip match).** The
  firmware opcode vocabulary has **no ENROLL/IDENTIFY/VERIFY/MATCH** — only
  GET_VERSION, RESET, PEEK/POKE, GET_STARTINFO, TAKE_OWNERSHIP_EX2,
  FRAME_{READ,ACQ,FINISH,STATE_GET,STREAM}, EVENT_{CONFIG,READ}, IOTA_FIND,
  PROVISION, GET_CERTIFICATE_EX, STORAGE_*, DB2_* (template DB), LED, etc.
  Matching is host software (`hMatcher`, `pMatcherIface->enrollFinish`,
  `_vfmMatchImageToTemplates`, `vfmEnrollAddImage`, QM matcher; templates stored
  via DB2/STORAGE).
- **Two distinct capture paths:**
  1. **Production enroll/verify** = `vfmUtilCaptureImage` (`fcn.180059420`) driving
     proto-IOCTL **0x65/0x191** + finger-detect (`fcn.1800609b0`,
     "SSI_CAPTURE_STATUS_FD_DETECTED") + EVENT_CONFIG. **Does NOT use FRAME_READ.**
  2. **Raw `FRAME_ACQ`/`FRAME_READ`** is reachable ONLY via the diagnostic/IPL
     "playback" IOCTL **`_tudorIoctlExt` `fcn.1800847e0`** (selector 0x65 ext;
     "_tudorIoctlExt: Invalid opCode"), which first loads SensorCfg/IPL-IOTA
     (`ePlaybackTagSensorCfg`/`ePlaybackTagIplIota`/`ePlaybackTagFrameDim` via
     `palTagValSetBlobDataProperty`) and runs the full
     `tudorCaptureStart(FRAME_ACQ)`→`FRAME_STATE_GET`→`FRAME_READ`→`FRAME_FINISH`
     sequencer. Frame-ready = proto-IOCTL **0x69**, 7-byte reply, `byte[0]==2` and
     `byte[1]`==expected index (`[hSensor+0x69]`).
- **Root cause of our 0x0689 (medium-high conf):** pydrv issues a bare `FRAME_ACQ`
  then `FRAME_READ` **without** the diagnostic/IPL "playback" mode arming that
  `_tudorIoctlExt` does (SensorCfg/IPL-IOTA load + the full sequencer). The
  firmware refuses the raw read → MALFUNCTIONED.
- **Strategic assessment:** host image capture IS how this sensor works, but the
  **driver-blessed path is production proto-IOCTL 0x65/0x191 (SSI/finger-detect),
  not raw FRAME_READ.** Two options for Linux: (a) replicate the
  `_tudorIoctlExt` diagnostic arming (SensorCfg/IPL-IOTA setup) before
  FRAME_ACQ/READ; (b) replicate the production 0x65/0x191 SSI capture path.
  Either way images come out **raw** and need host-side processing/matching
  (Windows uses a proprietary matcher module; a Linux port needs its own, e.g.
  libfprint/NBIS). No on-chip match to lean on. `rev.txt`-derived assumptions did
  NOT mislead the byte-level RE, but they omitted this production-vs-diagnostic
  split and the mode-arming precondition.

### Chunk 2 — FRAME_READ loop/seq: CONFIRMED (with corrections)
103 addrs: FRAME_READ builder **`fcn.180086cf0`** (opcode `0x7f`@`0x180086ec1`,
len 9@`0x180086eb5`); capture state machine **`tudorCaptureProcess fcn.18007ebc0`**;
readiness poll **`fcn.18007f780`**; proto dispatcher **`fcn.180085090`**; PAL
`fcn.1800680b0`.
- FRAME_READ = 9 bytes `7f <seq u16> 0000 ffff 0003` (LE) — CONFIRMED.
- **seq field = `word[hSensor+0xa0]`** (103; note 104 used `+0x90`): reset to 0 in
  FRAME_ACQ builder (`0x18008714c`), `++` only after a successful read
  (`0x180086ff7-09`), never synced to the interrupt frame index ⇒ **first read
  seq=0** CONFIRMED.
- **CORRECTION:** readiness poll uses proto-IOCTL **`0x69`** (not `0x6a`); generic
  sender uses proto-IOCTL **`0x67`**. Both return/ride cached host-side data.
- **NO on-wire command occurs between a successful FRAME_ACQ and FRAME_READ**
  (CONFIRMED): the state machine only reads the cached host event queue
  (`tudorEventDataGet fcn.18007fc60`) + the cached interrupt report (0x69). A Linux
  client needs nothing on the wire between ACQ and READ — just observe frame-ready
  (poll EP 0x83) then send 0x7f with seq 0,1,2,…
- FRAME_FINISH (0x81) NOT in the read loop (CONFIRMED; it's separate teardown).
  104-only SET_POWER_POLICY absent in 103 (CONFIRMED).

### RECONCILED ROOT CAUSE of 0x0689 (Chunks 2+3)
`tudorCaptureStart` (`fcn.18007e7d0`) does **pre-FRAME_ACQ arming** that pydrv
omits, in this order:
```
fcn.18007fab0  (pre-acq setup)
malloc capture ctx -> [hSensor+0xa8];  [hSensor+0xc4]=1 (capturing flag)
[ctx+0x14]=flags; [ctx+0x18]=flags2
fcn.18007fb30  (arm DRDY / config)          <-- likely EVENT_CONFIG / mode arm
[hSensor+0x69]=0  (interrupt-seq baseline)
FRAME_ACQ (0x80)
```
And per Chunk 3, the raw FRAME_ACQ/READ chain is reached only via the diagnostic
IOCTL `_tudorIoctlExt` (`fcn.1800847e0`), which first loads **SensorCfg + IPL-IOTA**
blobs (`ePlaybackTagSensorCfg`/`ePlaybackTagIplIota`). **In our on-device test the
frame WAS ready (interrupt byte0=2) yet we got `0x0689 = SENSOR_MALFUNCTIONED`
(illegal state), NOT `0x5b6 = FRAME_NOT_READY`.** ⇒ the sensor isn't complaining
"too early"; it's **not in the armed capture MODE**. pydrv sends a bare
`FRAME_ACQ` without the `fcn.18007fab0`/`fcn.18007fb30` arming (and/or the
SensorCfg/IPL-IOTA mode load) ⇒ MALFUNCTIONED.
- **Alt path:** replicate the production capture (`vfmUtilCaptureImage` →
  proto-IOCTL 0x65/0x191 + finger-detect) instead of the raw diagnostic path.

### ARMING SOLVED (2026-07-23) — EVENT_CONFIG(0x86) mask 0x1000 before FRAME_ACQ
Arming-RE subagent decoded the pre-FRAME_ACQ steps in `tudorCaptureStart`
(103 `fcn.18007e7d0`/`fcn.18007e6a0`):
- `fcn.18007fab0` (pre-acq): **host-side only** — frees the old capture ctx. No wire.
- `fcn.18007fb30` ("arm/DRDY"): **THE arming command** — calls
  `fcn.180080720(hSensor, 0x1000)` → builds & sends **`EVENT_CONFIG (0x86)` with
  mask `0x1000` → event id `0x18` (frame-ready/DRDY)**. Logs "Capture started".
- `_tudorIoctlExt` SensorCfg/IPL-IOTA "playback" load: **host-side only** (stores
  blobs via `palTagValSetBlobDataProperty`); no wire command.
So the ONLY missing on-wire step vs pydrv is the frame-ready `EVENT_CONFIG`.
- **EVENT_CONFIG(0x86) wire format** (37 = 0x25 bytes, LE; verified in
  `fcn.180080c30`/`fcn.180087820`): opcode + **two identical 4×u32 event bitmaps**
  (for event id `b`: word `b>>7`, bit `1<<(b&0x1f)`) + **u32 event count**. For
  mask 0x1000 (id 0x18 → word0 bit24): the 37 bytes are
  `86 | 01000000 00000000 00000000 00000000 | 01000000 00000000 00000000 00000000 | 01000000`.
  (Mask→id table: 0x100→2,0x80→1,0x04→6,0x08→7,0x10→8,0x20→9,0x01→3,0x02→4,
  0x40→5,**0x1000→0x18**.) EVENT_CONFIG **replaces** the mask (not additive), so
  the driver switches to frame-ready for the capture window.
- **Note pydrv's `set_event_mask` encoding differs** (it packs the mask into all
  8 u32 words + trailing `0`, vs the driver's 4-word bitmap ×2 + count). It works
  for finger masks empirically, but the capture fix sends the **exact driver
  bytes** to be safe (`capture.py` `capture_frames`, committed `f092167`).
- **Fix applied:** `capture_frames()` now sends `EVENT_CONFIG(0x1000)` immediately
  before `FRAME_ACQ`.
- **RETEST RESULT (2026-07-24): arming is NECESSARY-CONTEXT but NOT SUFFICIENT.**
  COMM log confirmed the exact driver-format `EVENT_CONFIG(0x1000)` went out
  (`86 | 01000000 00×3 | 01000000 00×3 | count=1`, status 0x0000), `FRAME_ACQ`
  (mode-3) accepted (status 0x0000), frame latched (`02000000000101`, b0=2) — and
  `FRAME_READ(seq=0)` STILL returns **0x0689**. So EVENT_CONFIG(0x1000) alone does
  not unlock raw reads.
- **Conclusion:** the raw `FRAME_ACQ`/`FRAME_READ` path needs MORE than the frame
  event arm — consistent with Chunk 3: it is gated behind the `_tudorIoctlExt`
  diagnostic/IPL "playback" mode, which likely pushes SensorCfg/IPL-IOTA state to
  the sensor (or sets a mode) beyond what we've replicated. **Recommended pivot:
  the production capture path (`vfmUtilCaptureImage` → proto-IOCTL 0x65/0x191 +
  finger-detect + host software matcher)** rather than fighting the diagnostic
  raw-read path. (Deferred to a fresh session per plan.)
- Recovery note: the failed capture again left a half-open TLS session
  (plaintext → `15 03 03…` alert); cleared via USB `dev.reset()` + ~30s idle.

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

## PRODUCTION CAPTURE-PATH RE (2026-07-24) — PIVOTAL FINDING: `00bc` IS A MATCH-ON-CHIP SENSOR

A 7-way `re`-subagent fanout against the **production** capture code (Phase A/B of
the session plan) overturns the handoff premise ("production enroll/verify uses
`vfmUtilCaptureImage` → proto-IOCTL 0x65/0x191 + finger-detect + HOST-side
matching"). The corrected model, cross-checked 103≡104:

- **The Windows production path matches ON-CHIP (Match-In-Sensor, "Mis"/MFW), not on
  the host.** It never pulls a raw image to the host. `[RE-7, high conf]`
- **`0x65`/`0x191` are host-side WBDI notification event ids** (built by
  `_vfmUtilEventCreate` `fcn.1800604e0`, dispatched to a WBF callback), **NOT wire
  ops / proto-IOCTLs.** Do not send them to the sensor. `[RE-5, RE-6, high conf]`
- **`FRAME_READ (0x7f)` and `FRAME_STREAM (0x8b)` are quarantined to
  init/self-test (`_tudorInitDevice fcn.18007c320`) and the diagnostic
  `_tudorIoctlExt` dispatcher** — they are NOT on any production capture path.
  This is why our bare FRAME_ACQ→FRAME_READ returns `0x0689`: it's a diagnostic
  path gated behind the SensorCfg/FrameDim/IplIota "playback" arming. `[RE-6, high conf]`
- **The `CBiometricDevice::CaptureImage → vfmUtilCaptureImage (fcn.180059420)`
  graph is the WAKE-ON-FINGER / finger-presence path** (fed by
  `CBiometricDevice::NotifyWakeThread fcn.180006860`). It transports **no pixels**
  (its pixel-memcpy at `0x180059b6a` is dead code: src `var_80h`/len `var_78h`
  stay 0), yielding only a **24-byte metadata descriptor** at `[hSensor+0xa8]`
  (geometry words `[hSensor+0x77]`/`[+0x7f]`, a DRDY event word, format tag
  `0x50`). `[RE-6, high conf]`

### How Windows actually does enroll/verify (Match-In-Sensor)
- The WBDI adapter `synaFpAdapter103.dll` is a thin shim: it talks to the UMDF USB
  driver purely via **`CreateFileW` + `DeviceIoControl`** (imports confirmed; the
  USB DLL exports only `FxDriverEntryUm` — no callable capture/match exports).
  `[RE-7]`
- Adapter IOCTL codes (device type `0x44`, METHOD_BUFFERED):
  `0x442058`(func 0x816)=**primary VCSFW command channel** (opcode = inBuffer[0],
  inBuf 0x1088 / outBuf 0x18ac); `0x44202c`=CreateEnrollment, `0x44200c`=Update,
  `0x442010`=Commit, `0x442014`=CheckForDuplicate, `0x440014`(func 0x005)=
  **SensorAdapterStartCapture**; low-func control ops `0x002..0x00d` via driver
  `fcn.1800680b0`. `[RE-7]`
- `EngineAdapterAcceptSampleData` (`fcn.180001500`) requires size **== 0x58 (88)**
  and copies an **opaque 88-byte feature-set/template descriptor** (5×movups+movsd)
  into `[ctx+0x38]` — **no per-pixel work; the adapter has zero image/width/height/
  stride/bpp strings and no `w*h*bpp` allocation.** `[RE-7, high conf]`
- The matcher lives in the driver's `synaLib`/`CEisMisEIV` ("Match In Sensor")
  layer as a **thin command wrapper to the sensor's Matcher FirmWare (MFW)**:
  `mis{InitModule,EnrollStart,AddImage,GetTemplate,Finish}`,
  `misAuthImageToTemplates`, `misIdentifyMatchCmd (fcn.1800a4f20)`. Telemetry
  proves on-chip: `"Mismatch of qm struct size on host and MFW."`,
  `" #### Match Score 0x%X  threshold 0x%X ###"` (score+threshold **returned by the
  sensor**), `"Enroll stats: progress-%d, templateCount-%d, redundant-%d
  quality-%d rejected-%d"`. `[RE-7, high conf]`
- `VCS_RESULT_MATCHER_*` (incl. `MATCHER_MATCH_FAILED`, base @ `0x180146628`) are
  **firmware matcher reply statuses** — consistent with on-chip matching.
- A **Match-On-Host ("Moh") capability EXISTS but is dormant/secondary**:
  `_vfmUtilMohMatchImageToTemplates` (104 `fcn.18005da60`), `hMatcher`,
  `_vfmMatchImageToTemplates`; the driver imports `mscoree.dll` (a managed matcher
  could load). The **exercised** enroll/verify chain is `Mis` (on-chip). Whether
  `Moh` is ever selected is a runtime/config decision **not resolvable statically**.
  → *This dormant Moh path is what the earlier "Chunk 3" pass mistook for
  "host-matched, no on-chip match"; Chunk 3 also wrongly concluded there are no
  enroll/match opcodes — the `mis*` matcher commands ARE ordinary VCSFW opcodes
  (builder `fcn.1800a58c0`, opcode from `cx`).*

### Validated infrastructure (this session)
- **proto-IOCTL dispatcher `fcn.180085090`** (decodes DeviceIoControl func 1..0x69):
  `0x65` DEVICE_INFO (VID/PID, 6-byte reply, USB device descriptor); `0x66`
  GET_TLS_STATE (2-byte, EP0 vendor ctrl); **`0x67` SEND_CMD_DATA = the ONLY
  large/bulk VCSFW command channel** (bulk write + bulk read EP 0x81, TLS-wrapped;
  generic sender `fcn.18008a570` at `edx=0x67`, re-allocs reply to wire-reported
  length, TLS-unwrap `fcn.18008df80`); `0x68` DEVICE_RESET/WRITE_DFT; **`0x69`
  INTERRUPT_DATA_GET = host-cached 7-byte interrupt status (NO USB)** from
  `[handle+0x8c]`/`[+0x90]` (== pydrv `get_event_data()` on EP 0x83); `0x6a`→default
  error `0x71`. `[RE-5, high conf]`
- **Finger-detect gate** (`CCaptureImage::CheckForFingerPresence fcn.18000ed9c`):
  `EVENT_CONFIG(0x86)` with event ids **{FINGER_PRESS=1, FINGER_REMOVE=2}**
  (Windows mask 0x180), then `EVENT_READ(0x87)` until a decoded event **== 0x80
  (FINGER_PRESS)**; then re-arm mask 0x100 to await removal. pydrv's
  `SensorEventType` id↔mask table (1↔0x80, 2↔0x100, …, 24↔0x1000) is **correct**;
  event-read parse (12-byte records, byte0=id, seq `& 0x1f`) matches. `[RE-2, high conf]`
- **Production arming = EVENT_CONFIG(0x86 mask 0x1000 DRDY) + FRAME_ACQ(0x80) only**;
  the `_tudorIoctlExt` SensorCfg/FrameDim/IplIota "playback" load is **host-side
  (no wire)**. Endian helpers are identity (all wire fields LE). `[RE-4, RE-6]`

### Function/ID reference (103 Augusta; 104 differs only in layout unless noted)
| item | 103 addr / value |
|---|---|
| `vfmUtilCaptureImage` (wake path) | `fcn.180059420` (104 `fcn.18005ead0`) |
| `CBiometricDevice::CaptureImage` | `fcn.18000ebf4` |
| `CBiometricDevice::NotifyWakeThread` (thread entry) | `fcn.180006860` |
| `CCaptureImage::CheckForFingerPresence` | `fcn.18000ed9c` (104 `fcn.180023044`) |
| SSI capture state machine (FD_DETECTED/RESTART) | `fcn.1800609b0` |
| `tudorCaptureStart` (EVENT_CONFIG+FRAME_ACQ) | `fcn.18007e7d0` |
| `tudorCaptureProcess` (event/status state machine) | `fcn.18007ebc0` |
| `tudorCaptureGetImage` (hands out 24-byte desc) | `fcn.18007f240` |
| `_tudorCaptureImageHeaderFill` (24-byte desc) | `fcn.18007f8c0` |
| proto-IOCTL 0x69 status get | `fcn.18007f780` |
| proto-IOCTL dispatcher | `fcn.180085090` |
| generic VCSFW sender (proto 0x67) | `fcn.18008a570` |
| `_vfmUtilEventCreate` (0x65/0x191 host events) | `fcn.1800604e0` (104 `fcn.180060d10`) |
| matcher: `misIdentifyMatchCmd` / builder | `fcn.1800a4f20` / `fcn.1800a58c0` |
| FRAME_READ(0x7f) builder (diagnostic/init only) | `fcn.180086b60` |
| FRAME_STREAM(0x8b) builder (diagnostic/init only) | `fcn.180088490` |
| adapter primary cmd IOCTL / StartCapture IOCTL | `0x442058` / `0x440014` |
| `EngineAdapterAcceptSampleData` (88-byte desc) | adapter `fcn.180001500` |

Staged for this RE (sandbox `re-frameacq/`): `synaFpAdapter103.dll`,
`synaFpAdapter104.dll` (both extracted), plus `prod_seedmap.md` and per-task r2
dumps `prod_re1_flow.txt`/`prod_re2_fingerdetect.txt`/`prod_re3_getimage.txt`/
`prod_re4_arming.txt`/`prod_afl_103.txt`.

### STRATEGIC FORK for the Linux port (decision pending — DO NOT proceed to impl. yet)
The session goal ("get a fingerprint image on Linux via the production path") is
**not achievable as framed**: Windows production has no host-image path — it
matches on-chip. Two real options remain:

1. **MOC / on-chip (Match-In-Sensor) — NEW, mirrors how Windows actually works and
   how libfprint's `synaptics` bmkt driver handles the adjacent `06cb:00bd`.**
   RE the `mis*` VCSFW enroll/verify/identify opcodes + QM struct over the existing
   (working) Tudor TLS channel; drive on-chip enroll/verify; no host image, no NBIS.
   pydrv already has DB2/STORAGE template opcodes (currently unused).
2. **Image capture / Match-On-Host — the original `rev`/pydrv approach + this
   session's stated goal.** Requires unlocking the diagnostic FRAME_READ/FRAME_STREAM
   path past `0x0689` by replicating the SensorCfg/FrameDim/IplIota "playback"
   arming (host-side blob loads that likely must be pushed to the sensor), then
   host matching (libfprint/NBIS). This is the path that "hit multiple dead ends"
   upstream; static RE has plateaued on the exact arming.

Open items: exact `mis*` opcode bytes + QM struct (Strategy 1); the precise
IPL-IOTA playback push that unlocks raw frames (Strategy 2); whether `Moh` is ever
selected on Windows (needs dynamic capture). Per the session's "static-first, Frida
only if stuck" decision, a Windows dynamic capture is the fallback if the chosen
strategy stalls in static RE.

## MOC COMMAND SPEC (2026-07-24) — on-chip enroll/verify for the Linux port
Direction chosen: **Strategy 1 (Match-In-Sensor)**. This is the durable spec for
Phase C (pydrv). RE'd from `synaWudfBioUsb103.dll` (3-way `mis*`/DB2 fanout),
cross-checked vs 104. **All little-endian.** Confidence high unless marked.

### Model
`00bc`/Augusta matches ON-CHIP: the sensor captures + extracts + matches + stores
templates internally. **The host never sends or receives pixels.** The host only:
(a) arms capture (finger-detect + FRAME_ACQ), (b) issues small **matcher commands**
(a tiny VCSFW opcode + a "QM command struct" body), (c) persists/loads template
**blobs** via DB2. (Contrast: 104/Tudor `00be` appears to match on HOST via a
bundled QM math lib — which is why the `rev`/pydrv image-capture design was built
for `00be` and does NOT apply to `00bc`. `[MOC-1]`)

### Matcher command channel
- Small opcode set multiplexed by a **QM command struct** in the request body;
  sub-operation selected by fields in that struct, not distinct opcodes.
  - **`0x96`** = enroll-family (misEnrollStart / AddImage / Finish/Commit; plus a
    nonce/challenge variant). Builder `fcn.1800a4600` (AddImage), `fcn.1800a4120`
    (start/nonce), `fcn.1800a4bf0` (finish). QM struct size validated **60 (0x3c)**.
  - **`0x99`** = `misIdentifyMatchCmd` (verify/identify). Builder `fcn.1800a4f20`.
    QM result size validated **36 (0x24)**.
- Generic matcher-cmd allocator `fcn.1800a58c0(cx=opcode, edx=body_len)`: wire buf =
  `[opcode:u8][zero body of body_len]`; sent via sensor-iface vtbl `[+0xa0]` =
  `tudorSendAnyCommand` (= normal TLS-wrapped SEND_CMD_DATA / proto-IOCTL 0x67).
- LE field helpers `fcn.1800b6380`(u32)/`fcn.1800b63b0`(u16) are identity.
- mis module handle global `[0x18015af98]` (null-checked before every mis op).

### ENROLL (opcode 0x96)
State machine: `misInitModule` → `CEisMisEIV::EnrollmentCreate` → **misEnrollStart**
→ loop{ arm capture (see below) → **misEnrollAddImage** → read 60-byte stat →
inspect progress } until **progress==100** → **misEnrollFinish/EnrollmentCommit**
→ **DB2 WRITE_OBJECT (0xa2)** to persist. Failure → `EnrollmentDiscard`.
- **Host sends NO image.** `misEnrollAddImage` body is a few bytes (opcode + u16
  sub-op=2 + small QM header); the sensor extracts features from its internally
  captured frame. `[MOC-1, high conf]`
- **AddImage 60-byte QM stat** (offsets within the returned stat struct): `+0x02`
  u8 qmStatus; `+0x14` u32 templateCount; `+0x18` u32 quality (==1 ⇒ redundant);
  `+0x1c` u32 progress %; `+0x24` u32 redundant/reject; `+0x28` u16 finalQuality.
  Log: "Enroll stats: progress-%d, templateCount-%d, redundant-%d quality-%d
  rejected-%d". Result codes: **305 (0x131)** = more images needed; **304 (0x130)**
  = failed / fixed-pattern (fixed-pattern limit = 4). No fixed image count — loop
  until progress 100.
- Enrolled template handle lives at `session_ctx+0x60`; `misEnrollGetTemplate`
  returns it locally (no wire cmd). `misEnrollSessionSave/Restore` (de)serialize the
  0x70-byte session for pdata persistence `[layout UNKNOWN, medium]`.

### VERIFY / IDENTIFY (opcode 0x99, `misIdentifyMatchCmd`)
State machine: load templates from flash → `SetTemplateList` → `misAuthStart`
(allocs 0xA8 session) → arm capture → `misAuthImageToTemplates` → **misIdentifyMatchCmd
(0x99)** → parse 36-byte result → **score > host-supplied threshold ⇒ MATCH** →
optional `misAuthUpdateTemplate` (+ DB2 rewrite) → `misAuthGetResult` → `misAuthFinish`.
- **0x99 request** (after opcode byte): `u32 nTemplates`; then
  IF nTemplates>0: `u32 list_len(=n*16)` + `n × 16-byte template refs (TUIDs)`;
  ELSE: `u32 blob_len` + `feature_blob`. (A 16-byte header block tagged `0x642` is
  attached by the 3-blob sender.)
- **0x99 reply** (base = reply+2 after 2-byte status): `+0x10` u32 qm_result_size
  (==0x24/36); `+0x14` u32 auxA_len; `+0x18` u32 auxB_len; `+0x1c` 36-byte QM result;
  then auxA, auxB (palTagVal containers, tags 1/2/3 → matchStrength/index/update).
  Match fields (score/matchIndex/matchStrength/templateUpdate/updatedRef) — meaning
  HIGH, exact intra-36B offsets MEDIUM (103 reads them via tag-value, not fixed
  slicing). **Threshold is host-supplied** (from host session state), sensor returns
  raw score. `misAuthGetResult` sub-ops `0x2711/0x2712/0x2713` fetch matched-TUID /
  payload / signed-result artifacts.

### Capture arm (precedes each AddImage / match) — reuses known frame infra
`EVENT_CONFIG(0x86)` finger/DRDY arm → `FRAME_ACQ(0x80)` → wait finger-detect via
`EVENT_READ(0x87)` (finger ids {1,2}, wait FINGER_PRESS 0x80) / cached interrupt.
Wake-on-finger; no host pixels. (Exact per-enroll mask/order MEDIUM — reuse the
finger-detect gate from the production-path section above.)

### DB2 template storage (opcodes CORRECTED vs pydrv)
Request wire = `[opcode:u8][body]` (allocator `fcn.1800af420`, sender `fcn.1800af510`
via `tudorSendAnyCommand`). **Templates are DB2 objects on sensor flash; object type
tag = `0x20`.** Host caches 112-byte descriptors + serialized blobs; sensor copy is
authoritative.
| cmd | opcode | notes |
|---|---|---|
| GET_DB_INFO | **0x9e** | req `pack("<BB",0x9e,1)`; resp has per-type object counts (types 1/2/3) |
| DB_OBJECT_CREATE | 0x47 | legacy DB1; NOT the template path |
| GET_OBJECT_LIST | **0x9f** | req = op + type(u8) + 3 pad + 16-byte UID; resp = status + count×16-byte UIDs |
| GET_OBJECT_INFO | **0xa0** | req like LIST; resp payload size @ objinfo+0x2e |
| GET_OBJECT_DATA | **0xa1** | req = op+type+16B UID; resp: datalen u32 @+4, payload @+8 (**template blob read**) |
| **DB2_WRITE_OBJECT** | **0xa2** | **MISSING in pydrv.** type2: op+type+const1+16B UID + len u32@0x1d + payload@0x21 |
| DELETE_OBJECT | **0xa3** | req = op+type+16B UID |
| **DB2_CLEANUP** | **0xa4** | **pydrv wrongly aliases this to 0xa3.** body minimal `[UNKNOWN, medium]` |
| FORMAT | **0xa5** | destructive DB2 wipe `[body untraced]` |
- STORAGE_PART_{READ,WRITE} 0x40/0x41 & STORAGE_INFO_GET 0x3e = host-partition
  (pairing-data) ops, NOT the per-template path.

### Secure storage gating (verify empirically)
`CEisMisEIV::AuthenticateUserStorageOnSensor`, `SapRequest`, secureBio nonce exist =
a SAP / secure-storage auth. Plain DB2 senders issue 0x9e/0x9f/0xa0/0xa1/0xa2
directly over the established TLS channel with no visible per-op SAP handshake ⇒
**reads likely work without SAP; writes MAY require it.** Top empirical unknown.
`[MOC-3, medium]`

### PHASE C PLAN (updated 2026-07-24 after RES-1/2/3 — supersedes the stale gap list)
Exact wire layouts are in "RESIDUAL RE RESOLVED" below. Corrected understanding:
- **No frame-capture arm.** Enroll/verify do NOT send `EVENT_CONFIG(0x86)`/
  `FRAME_ACQ(0x80)`/`FRAME_READ`/`EVENT_READ(0x87)`. The sensor captures + extracts
  on-chip on the `0x96`/`0x99` matcher command. (⚠ removed the earlier
  "capture-arm reuse" item — it was wrong.)
- **No SAP needed** for DB2 read/write over the existing TLS channel.
- `misEnrollSessionSave/Restore` are 103 stubs → persistence = the DB2 template
  object, not a session blob.

Recommended ordered steps (safe → risky):
1. **comm.py DB2 enum fix (safe):** add `DB2_WRITE_OBJECT=0xa2`; fix
   `DB2_CLEANUP=0xa4` (currently wrongly `0xa3`, aliasing `DELETE_OBJ`). Keep
   `FORMAT 0xa5` on the NEVER-run list (destructive).
2. **DB2 read path (read-only, on-device validation):** implement `GET_DB_INFO 0x9e`
   → `GET_OBJECT_LIST 0x9f` (filter object type `0x20`) → `GET_OBJECT_INFO 0xa0` /
   `GET_OBJECT_DATA 0xa1`. Run on the tablet to enumerate existing template objects.
   Zero risk; validates the DB2 layer + our layouts before any write/enroll.
3. **Matcher command layer:** `mis*` builders — `0x96` (sub-op 1/2/4) and `0x99`
   (const1 + list_len/blob_len + payload), QM reply parse (60B enroll stat / 36B
   match result), over the existing TLS `send_command`.
4. **Enroll state machine:** misEnrollStart → loop misEnrollAddImage until stat
   `progress(u8@+2)==100` (handle 305=more/304=fail) → misEnrollFinish. NO FRAME_ACQ.
5. **Template persist:** WRITE_OBJECT `0xa2` (type `0x20`). ⚠ **BLOCKER to resolve
   first:** the stored blob is a host-built `pEncryptedTemplate` (tuid16 + 60B QM
   descriptor + user/sub-id + a crypto wrap) whose wrapping is NOT yet decoded —
   templates may not round-trip until we RE/replicate it, or find a raw-store path.
6. **Verify/identify:** load templates (step 2) → SetTemplateList → misAuthStart →
   `misIdentifyMatchCmd 0x99` → parse 36B result → match iff `score > threshold`
   (host-chosen) → optional misAuthUpdateTemplate + WRITE_OBJECT rewrite.

Genuinely-open items (resolve on-device / dedicated RE during Phase C):
- **`pEncryptedTemplate` wrap/crypto** (step 5 blocker) — the main risk.
- Finger-present trigger/timing vs the `0x96` AddImage (likely command-triggered
  on-chip; the finger-detect EVENT path may still be needed for host UI/sync).
- Interior of the 16-byte TUID; unused 36B/60B stat dwords; whether firmware ever
  rejects DB2 writes outside a SAP session (expected: no).

## RESIDUAL RE RESOLVED (2026-07-24) — exact wire layouts for Phase C
3-way `re` fanout (RES-1/2/3) pinned the byte layouts + resolved two premises.
**All little-endian; request buffer = `[opcode:u8][body…]`.** Two corrections to the
MOC COMMAND SPEC above are marked ⚠.

### ⚠ Correction 1 — MOC enroll/verify does NOT arm FRAME_ACQ/EVENT_CONFIG
RES-3 traced the enroll add-image path (`CEisMisEIV::EnrollmentUpdate fcn.180011050`
→ `vfmUtilEnrollAddImage fcn.180055300` → `vfmEnrollAddImage fcn.18004bd30`) and the
verify path and found **no `EVENT_CONFIG(0x86)`/`FRAME_ACQ(0x80)`/`EVENT_READ(0x87)`
in the MOC path**. Those belong to the separate wake/diagnostic path. On-chip
enroll/verify is driven **entirely** by the matcher commands `0x96`/`0x99` (+ QM
struct); **the sensor captures + extracts on-chip when it receives the command.**
`vfmEnrollAddImage` issues AddImage via sensor-iface vtable `[iface+0x40]` (=`0x96`
builder `fcn.1800a4600`) and, on the final image, GetTuid via `[iface+0x48]`.
⇒ **Phase C: do NOT arm FRAME_ACQ for enroll/verify.** Open on-device question:
how finger-present is signalled/timed relative to the `0x96` AddImage (likely the
command itself waits-for-finger on-chip; finger-detect events may be host-UI only).

### ⚠ Correction 2 — SAP / secure-storage is NOT required for DB2
RES-2 proved (disjoint call graph) that DB2 read/write go solely through allocator
`fcn.1800af420` + sender `fcn.1800af510` → `call [ctx+0xa0]` (tudorSendAnyCommand),
with **no** SAP call. `AuthenticateUserStorageOnSensor`/`SapRequest` are a separate
WBDI/SSI secure-session (host↔service trust + enroll-commit), on a different object
(`this+0x10`). ⇒ **A Linux driver that owns TLS can do DB2 read/write WITHOUT SAP.**
(Residual risk only if firmware itself rejects writes outside a SAP session — the
DLL's own code does not; verify on-device.)

### Matcher requests (opcode byte at buf[0]; offsets are body = buf+1)
- **misEnrollStart** (`fcn.1800a4120`, body 13B): `struct.pack('<B I I I B', 0x96, 1, nonce_present, nonce, 0)` — sub-op **1**@+0; nonce_present@+4; nonce@+8.
- **misEnrollAddImage** (`fcn.1800a4600`, body 5B): `struct.pack('<B I B', 0x96, 2, 0)` — sub-op **2**@+0.
- **misEnrollFinish/Commit** (`fcn.1800a4bf0`, body 5B): `struct.pack('<B I B', 0x96, 4, 0)` — sub-op **4**@+0.
- **misIdentifyMatchCmd** (`fcn.1800a4f20`, body = n*16 + blob_len + 0xd):
  body[+0]=u32 **1** (constant); [+4]=u32 list_len(=n*16) OR [+8]=u32 blob_len; payload@+0xc.
  - template path: `pack('<B I I I', 0x99, 1, n*16, 0) + n×16-byte refs`
  - blob path:     `pack('<B I I I', 0x99, 1, 0, blob_len) + blob`
  - 16-byte template ref = opaque TUID (= DB2 object UID). `0x642` is a transport
    descriptor tag (not in the body). secureBio nonce fetched before the 0x99 send.

### Matcher replies (reply base skips 2-byte status; QM = reply+2; size u32 @ QM+0x10)
- **60-byte ENROLL stat** (0x96 AddImage; validated `QM+0x10==0x3c`; copied from QM+0x14).
  Field offsets **within the 60-byte stat** (⚠ corrects the earlier tentative map):
  `+0x02` **u8 progress%** (completion gate: `byte[stat+2]==0x64`==100);
  `+0x14` u32 **redundant**; `+0x18` u32 **quality**; `+0x1c` u32 **templateCount**;
  `+0x24` u32 **rejected**; `+0x28` u16 **finalQuality**; `+0x30` u32 completion flag.
  Log: "Enroll stats: progress-%d, templateCount-%d, redundant-%d quality-%d rejected-%d".
  Status codes: 305(0x131)=more images; 304(0x130)=failed/fixed-pattern (limit 4).
- **36-byte MATCH result** (0x99; validated `QM+0x10==0x24`; copied from QM+0x1c).
  **FIXED offsets (not tag-value):** `+0x00` u32 **matchScore**; `+0x14` u32
  **templateUpdate** flag; `+0x1c` u32 **updatedTemplateRef/index**. (matchIndex/
  matchStrength seen in host logs are host-computed, not direct wire fields.)
  **Threshold = host session `ctx+0x2c`; MATCH iff `score > threshold` (strict).**

### DB2 storage (framing: allocator `fcn.1800af420` sets buf[0]=opcode; resp fields @ resp+2)
- **GET_DB_INFO 0x9e** (`fcn.1800ad140`): req `pack('<BB',0x9e,1)`; resp 0x28B — u16s:
  +0 dummy, +2 verMaj, +4 verMin, +6 pversion(u32), +0xa UOP_len, +0xc TOP_len,
  +0xe POP_len, +0x10 tmplSlotSz, +0x12 paySlotSz, **+0x14 NumCurrentUsers**,
  +0x16 NumDeletedUsers, +0x18 NumAvailUserSlots, **+0x1a NumCurrentTemplates**,
  +0x1c NumDeletedTemplates, +0x1e NumAvailTmplSlots, **+0x20 NumCurrentPayloads**,
  +0x22 NumDeletedPayloads, +0x24 NumAvailPaySlots. (Auto-fires CLEANUP if
  NumDeletedUsers!=0 && NumAvailUserSlots==0.)
- **GET_OBJECT_LIST 0x9f**: req = `op + type(u8) + 3pad + 16-byte UID key`; resp =
  status + count×16-byte UID entries (count from GET_DB_INFO). Template entries have
  a leading `u32 type == 0x20` (filter in RetrieveTemplatesFromFlash).
- **GET_OBJECT_INFO 0xa0**: req like LIST; resp payload size @ objinfo+0x2e.
- **GET_OBJECT_DATA 0xa1**: req = `op+type+3pad+16B UID`; resp: `datalen u32 @+4`,
  payload @+8 (the template blob read).
- **WRITE_OBJECT 0xa2** (`fcn.1800ae2c0`, body = 0x24 + payload_len): type2/3 =
  `pack('<BB',type,1) + 2pad + uid16 + 8pad + pack('<I',payload_len) + payload`;
  type1 = `pack('<BB',type,1) + 2pad + id4`. Response: 16-byte object handle/UID @
  resp+0x04 (echoed to caller). **UID is host-supplied/echoed** (new-template UID is
  minted upstream in the enroll/QM path, NOT by this builder).
- **DELETE_OBJECT 0xa3** (`fcn.1800aea50`, body 0x14): `pack('<BB',0xa3,type)+2pad+uid16`;
  resp u16 deleted_objects @+2.
- **CLEANUP 0xa4** (`fcn.1800aee80`, body 1): `pack('<BB',0xa4,1)`; resp (8B) u16
  erased_slots@+2, u32 new_partition_version@+4.
- **FORMAT 0xa5** (`fcn.1800aec80`, body 0xc): `pack('<B',0xa5)+b'\x01'+11pad`; resp
  u32 new_partition_version@+4. (Destructive — on the NEVER-run list.)

### Auth session + template persistence
- **misAuthStart** allocs 0xA8 ctx: `+0x00` session id, `+0x2c` **threshold**,
  `+0x40/+0x48` matched-TUID size/ptr, `+0x50/+0x58` payload, `+0x60/+0x68` signed
  result, `+0x90` match time.
- **misAuthGetResult** (`fcn.1800a3270`) sub-ops: **0x2711**→matched TUID (ctx+0x40/48),
  **0x2712**→payload (ctx+0x50/58), **0x2713**→signed result (ctx+0x60/68). Buffer-size
  negotiation: if caller capacity < needed → write needed + return status 0x74.
- **misEnrollSessionSave/Restore are UNIMPLEMENTED STUBS in 103** (return 0x71). ⇒
  **persistence = the DB2 template object, not a session blob.**
- **Template blob is built HOST-SIDE**: `vfmGetTemplate fcn.18004c780` assembles a
  `pEncryptedTemplate` from the enroll ctx (on-chip tuid16 + 60-byte QM descriptor +
  user/sub id + a crypto wrap), then `tudorCmdWriteObject` → **WRITE_OBJECT 0xa2**
  (object type tag 0x20). ⚠ **Phase C complication:** the exact template
  encryption/wrapping (`pEncryptedTemplate`) is NOT fully decoded (host-key wrap of
  {tuid16 + QM descriptor + ids}) — needs its own RE or on-device probing before
  templates can round-trip. `RetrieveTemplatesFromFlash` reads them back via 0xa1.

### Still-open (on-device or further RE)
- Finger-present trigger/timing vs the `0x96` AddImage (likely command-triggered
  on-chip capture; confirm on device).
- The `pEncryptedTemplate` wrap/crypto used by WRITE_OBJECT 0xa2.
- Whether firmware accepts DB2 writes without a SAP session (expected yes).
- Exact interior of the 16-byte TUID; unused 36B/60B stat dwords.
- 104 layouts differ (divergent generation) — not needed for `00bc`.

## PHASE C ON-DEVICE PROGRESS (2026-07-24) — enroll blocked on add_image crash
Implemented in `pydrv` (branch `00bc-dev`): `comm.py` DB2 enum fix + MOC opcodes;
`sensor/db2.py` (DB2 read), `sensor/moc.py` (SensorMatcher 0x96/0x99 + QM parse);
diag probes `db2_probe.py`, `enroll_probe.py`. Validated live on `06cb:00bc` fw 10.1:
- **DB2 read WORKS.** `GET_DB_INFO` → 0 users/0 templates/0 payloads (DB empty; 11
  template slots, slot size 48). `GET_OBJECT_LIST` framing = `status(2) + u16 count +
  count×16B UID`. Layouts confirmed. **SAP not needed for DB2 reads** (as predicted).
- **`misEnrollStart` (0x96/1, 13B `96 01 00…00`) is ACCEPTED** (reply `000000000000`).
- **Frame capture ARMING WORKS.** `EVENT_CONFIG(0x86, DRDY bit24)` + `FRAME_ACQ(0x80,
  mode3)` (the exact `capture.py` bytes) → status 0, and a finger press latches a
  frame on-chip (interrupt report `02 00 00 00 00 01 00`, ev[0]=2, frame idx 1).
- **BLOCKER: `misEnrollAddImage` (0x96/2, `96 02 00 00 00`) CRASHES/RESETS the sensor**
  every time (USB disconnect → `GET_VERSION 0x0315`), **whether or not a frame is
  armed/latched**. The request bytes are confirmed correct by reading the builder
  `fcn.1800a4600` disasm directly (opcode + u32 sub-op=2; arg2 is a host-side OUT
  buffer for the returned 16B TUID, not sent; reply parsed as 60B stat at reply+0x16).
  Same opcode/send path as the working `enroll_start`, so it is a **STATE** problem,
  not a format bug.
- **Leading hypothesis:** the one WIRE step Windows performs during enroll that we
  skip is **`CEisMisEIV::AuthenticateUserStorageOnSensor` (SAP)** — resolved as the
  `[rax+0x108]` virtual in `EnrollmentUpdate` (fcn.180010f10), a one-time
  (flag-gated) call BEFORE the first `misEnrollAddImage`. The on-chip matcher likely
  requires a SAP-authenticated secure session before add-image. SAP uses `SapRequest`
  (fcn.180012510→…) on the SSI object (`this+0x10`) with a secureBio nonce +
  challenge/response state machine (status bytes 0x74/0x76); its exact wire opcode is
  **UNDECODED**. (Note this refines "Correction 2": SAP is not needed for DB2, but
  appears required for the MATCHER/enroll.)
- **Recovery:** a crashed add_image leaves the sensor stuck (`0x0315`); clear with USB
  `dev.reset()` + **~45s** idle (30s was sometimes insufficient after a matcher crash).
- **Open decision (see chat):** RE+implement SAP handshake (partially decoded, may
  involve crypto) vs Windows/Frida dynamic capture of a real enroll (blocked by
  topology: Windows enroll broken on this tablet) vs reconsider. This is the
  "static-first, Frida-if-stuck" fork.

### SAP RE (2026-07-24) — root cause CONFIRMED; static wall reached
Focused `re` pass on `AuthenticateUserStorageOnSensor`/`SapRequest`:
- **ROOT CAUSE CONFIRMED:** `vfmEnrollAddImage` (fcn.18004bd30) hard-gates on an
  on-chip **auth session**: `"Auth session is not established."` (@0x180141cd8) →
  returns `0x6f` when `[ctx+0x10]==0`. Windows NEVER sends `0x96/2` cold; our sending
  it without the session is what faults the sensor. The session is populated by
  `CEisMisEIV::AuthenticateUserStorageOnSensor` (fcn.18000fd90), gated in
  `EnrollmentUpdate` (fcn.180010f10) by `[rbx+0xc8]!=0 && [rbx+0xcc]==0` → run **once**
  per fresh enroll, order **Auth → EnrollPrep → AddImage loop**.
- **SAP op sequence** (fcn.18000fd90): `vfmUtilSessionGetDeviceHandle` →
  `vfmSetParamBlob(id=0x6a, <SAP req>)` → `vfmUtilAuthImage` (loops SapRequest
  challenge/response, status `0x74`=continue / `0x76`=answer-challenge / `0`=done) →
  `vfmGetParamBlob(id=0xcb, 32B)` + `vfmGetParamBlob(id=0xc9, 2048B)`. secureBio nonce
  = **8 bytes**, fetched via SSI vtable `[ssi+0x50]` (edx=8); nonce size set via
  `misSetParameter` id `0x15`.
- **NO extra host crypto** (HIGH conf): all CryptoAPI stays in the TLS/pairing region
  (0x18007xxxx), unreachable from the SAP path. SAP is opaque challenge/response
  relayed over the **existing TLS**; any signing/derivation is ON-CHIP. ⇒ no host
  key to replicate — feasibility-wise the good case.
- **STATIC WALL (the blocker):** the literal VCSFW wire opcodes + palTagVal byte
  layouts for the SAP send, the nonce fetch, and the `vfmGetParamBlob` reads are
  **runtime storage-vtable indirect dispatches** (`[0x18015aed0]+0x18`,
  `[ssi+0x50]`; vtable populated by constructor fcn.18001be60) — **NOT statically
  resolvable**. The challenge/response payload is firmware-defined/opaque.
- **⇒ Two opaque secure pieces now block MOC**: (1) this SAP session (enroll+verify),
  (2) the `pEncryptedTemplate` wrap (persistence). Both realistically need a **Windows
  TLS-decrypted dynamic capture** (Frida hooking the plaintext command buffer) to
  resolve — the sanctioned "if stuck" fallback. Topology caveat unchanged (Windows
  enroll broken on this tablet since Linux took pairing).
