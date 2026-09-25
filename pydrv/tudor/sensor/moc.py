from __future__ import annotations

import struct
import time
import logging
import tudor
from .sensor import *
from .event import SensorEventType
from tudor.win.tagval import WinTagValContainer

#Match-In-Sensor (MOC) matcher command primitives, RE'd from synaWudfBioUsb103.dll.
#The matcher multiplexes a small VCSFW opcode set by a "QM command struct" in the body:
#  enroll     = opcode 0x96, sub-op u32 at body+0 (START=1, ADD_IMAGE=2, FINISH=4)
#  ident/match= opcode 0x99, misIdentifyMatchCmd
#Request buffer = [opcode:u8][body]; comm.send_command TLS-wraps it. Reply: status at
#resp[:2], QM struct at resp[2:]; size u32 at QM+0x10; enroll stat copied from QM+0x14
#(60 bytes), match result from QM+0x1c (36 bytes). All little-endian.

#Enroll sub-ops (u32 at body+0 of opcode 0x96), from the Windows dynamic capture.
ENROLL_START = 1
ENROLL_ADD_IMAGE = 2
ENROLL_COMMIT = 3        # 0x96/3 : finalize+persist template (carries TUID + user id)
ENROLL_END = 4           # 0x96/4 : release the enroll session

QM_ENROLL_STAT_SIZE = 0x3c   # 60
QM_MATCH_RESULT_SIZE = 0x24  # 36

#mis-layer result codes surfaced by the enroll orchestration
ENROLL_RES_MORE = 305   # 0x131 more images needed
ENROLL_RES_FAIL = 304   # 0x130 failed / fixed-pattern
MATCHER_NO_MATCH = 0x0509   # verify/identify reply status when no template matched

class CaptureCancelled(Exception):
    """Raised out of the capture/enroll poll loops when a caller-supplied should_cancel()
    returns True (e.g. libfprint asked us to cancel the current operation). Lets the driver
    unwind cleanly and release the on-chip session instead of blocking on finger events."""
    pass

#--- Per-image capture recipe, byte-for-byte from the Windows enroll capture (2026-09-22).
#These are Augusta-generic fixed captured values (validated on our 06cb:00bc). They arm the
#on-chip frame capture that precedes each add_image; the host receives no pixels.
#
#0x39 = LED_EX2 / "SensorCfg-IPL playback" config, pushed around each capture. Wire form:
#  [0x39][u32 counter][static record tail]. Only the leading u32 counter varied across the
#42 captured sends (the record tail is identical); 0x3e8 is a safe replayable value.
LED_EX2_COUNTER = 0x3e8
_LED_EX2_TAIL = bytes.fromhex("4b000000078c00208c8c000000000000000000004b000000010000200000000000000000000000004b000000018c00200000000000000000000000004b0000000100002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
LED_EX2_CFG = struct.pack("<BI", 0x39, LED_EX2_COUNTER) + _LED_EX2_TAIL
#FRAME_ACQ production 17-byte form (NOT the 25-byte diagnostic mode-3 that crashed us):
#  [0x80][u32 flags=0x0c][u32 num_frames=1][u32 0x08000001][u32 0x00010101]
#The last two u32s are the fixed production capture-mode flags for the matcher path.
FRAME_ACQ_17B = bytes.fromhex("800c000000010000000100000801010100")
FRAME_FINISH = bytes([0x81])   # 0x81 = FRAME_FINISH (teardown after each armed capture)

#--- enroll_commit (0x96/3) body, RE'd from the 103 builder fcn.1800af17f (2026-09-22)
#and verified to byte-reconstruct the Windows dynamic capture. The commit wire is:
#  [0x96][u32 sub-op=3][u32 0][u32 payload_len][payload]
#where payload_len is set at buf+9 (=0x6f/111 in the capture) and payload (111B) is a
#template descriptor:
#  [_CD_HDR 6B][TUID 16B][_CD_MARKER 2B][u32 identity_len][WINBIO_IDENTITY][_CD_TRAILER 7B]
#The identity is a standard Windows WINBIO_IDENTITY struct:
#  [u32 Type][u32 Size][Data[SECURITY_MAX_SID_SIZE=68]]  (fixed 76-byte slot)
#For a SID (Type=3), Size is the real SID byte-length and Data holds the SID + zero pad.
#Length fields (identity_len, payload_len) are recomputed from the actual identity, so
#an arbitrary-length user id is supported (Data is padded to >=68 to match Windows).
WINBIO_ID_TYPE_NULL = 0
WINBIO_ID_TYPE_WILDCARD = 1
WINBIO_ID_TYPE_GUID = 2
WINBIO_ID_TYPE_SID = 3
SECURITY_MAX_SID_SIZE = 68   # WINBIO_IDENTITY.Value.AccountSid.Data[68]

_CD_HDR = bytes.fromhex("000010000000")        # descriptor header (6B): u32 0, then tuid_len 0x10 (u16)
_CD_MARKER = bytes.fromhex("0100")             # identity-present marker / count = 1
_CD_TRAILER = bytes.fromhex("020001000000f7")  # fixed 7-byte enroll-commit trailer

#The 28-byte Windows SID from the ground-truth capture. Used as the default identity so
#enroll_commit() with no user id still reproduces the validated commit exactly; real
#Linux enrollments pass their own identity (see driver enroll command).
WIN_CAPTURED_SID = bytes.fromhex("010500000000000515000000619fb3c507285b02c10f762de9030000")

def make_linux_sid(rid : int) -> bytes:
    """Builds a well-formed 28-byte SID identity for a Linux user by reusing the proven
    captured SID structure (revision/authority/sub-authorities) and substituting only the
    trailing RID (last sub-authority). Keeps the exact byte shape the sensor accepted while
    making each enrolled user unique. rid is a 32-bit host-chosen id (e.g. derived from a
    label or an incrementing counter)."""
    return WIN_CAPTURED_SID[:24] + struct.pack("<I", rid & 0xffffffff)

def build_enroll_commit(tuid : bytes, user_id : bytes, identity_type : int = WINBIO_ID_TYPE_SID) -> bytes:
    """Builds the 0x96/3 enroll-commit request for the given on-chip TUID and user identity.
    user_id is the raw identity bytes (e.g. a SID); it is padded into the fixed 68-byte
    WINBIO_IDENTITY Data field (Windows always sends 68). identity_type selects the
    WINBIO_IDENTITY_TYPE (3=SID as captured, 2=GUID). All length fields are computed."""
    assert len(tuid) == 16
    data = user_id + bytes(max(0, SECURITY_MAX_SID_SIZE - len(user_id)))
    identity = struct.pack("<II", identity_type, len(user_id)) + data
    payload = _CD_HDR + tuid + _CD_MARKER + struct.pack("<I", len(identity)) + identity + _CD_TRAILER
    return struct.pack("<BII", tudor.Command.MATCHER_ENROLL, ENROLL_COMMIT, 0) + struct.pack("<I", len(payload)) + payload

class EnrollStat:
    """60-byte QM enroll stat (misEnrollAddImage reply)."""
    def __init__(self, raw : bytes):
        assert len(raw) >= QM_ENROLL_STAT_SIZE
        self.raw = raw
        self.progress = raw[0x02]                                  # u8, ==100 => complete
        self.redundant, = struct.unpack_from("<I", raw, 0x14)
        self.quality, = struct.unpack_from("<I", raw, 0x18)
        self.template_count, = struct.unpack_from("<I", raw, 0x1c)
        self.rejected, = struct.unpack_from("<I", raw, 0x24)
        self.final_quality, = struct.unpack_from("<H", raw, 0x28)

    @property
    def complete(self): return self.progress >= 100

    def __repr__(self):
        return ("EnrollStat(progress=%d templateCount=%d quality=%d redundant=%d rejected=%d finalQuality=%d)"
                % (self.progress, self.template_count, self.quality, self.redundant, self.rejected, self.final_quality))

class MatchResult:
    """36-byte QM match result (misIdentifyMatchCmd reply) + optional aux tag-value blobs."""
    def __init__(self, raw : bytes, auxA : bytes = b"", auxB : bytes = b""):
        assert len(raw) >= QM_MATCH_RESULT_SIZE
        self.raw = raw
        self.matched_tuid = None
        self.score, = struct.unpack_from("<I", raw, 0x00)
        self.template_update, = struct.unpack_from("<I", raw, 0x14)
        self.updated_ref, = struct.unpack_from("<I", raw, 0x1c)
        self.auxA = WinTagValContainer.frombytes(auxA) if len(auxA) > 0 else None
        self.auxB = WinTagValContainer.frombytes(auxB) if len(auxB) > 0 else None

    def matched(self, threshold : int) -> bool:
        return self.score > threshold

    def __repr__(self):
        return ("MatchResult(score=0x%x templateUpdate=%d updatedRef=%d)"
                % (self.score, self.template_update, self.updated_ref))

class SensorMatcher:
    """MOC matcher command primitives (no state machine / no finger sync)."""

    def __init__(self, sensor : Sensor):
        self.sensor = sensor

    def _send(self, req : bytes, resp_size : int, timeout : int):
        resp = self.sensor.comm.send_command(req, resp_size, timeout, raw=True)
        status = struct.unpack("<H", resp[:2])[0] if len(resp) >= 2 else -1
        return status, resp

    #--- enroll (opcode 0x96) ---

    def enroll_start(self, nonce_present : int = 0, nonce : int = 0, timeout : int = 5000) -> bytes:
        #13-byte request: [0x96][u32 sub-op=1][u32 nonce_present][u32 nonce]
        req = struct.pack("<BIII", tudor.Command.MATCHER_ENROLL, ENROLL_START, nonce_present, nonce)
        status, resp = self._send(req, 0x80, timeout)
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        return resp

    def enroll_add_image(self, timeout : int = 15000):
        #5-byte request: [0x96][u32 sub-op=2]. Returns (EnrollStat, tuid). tuid (reply[2:18])
        #is zero until the final image, then the sensor-assigned 16-byte template UID.
        req = struct.pack("<BI", tudor.Command.MATCHER_ENROLL, ENROLL_ADD_IMAGE)
        status, resp = self._send(req, 0x100, timeout)
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        if len(resp) < 0x16 + QM_ENROLL_STAT_SIZE:
            raise Exception("enroll_add_image short reply (%d): %s" % (len(resp), resp.hex()))
        qm_size, = struct.unpack_from("<I", resp, 0x12)
        if qm_size != QM_ENROLL_STAT_SIZE:
            raise Exception("QM enroll-stat size mismatch host=%d sensor=%d (qm struct on host and MFW)" % (QM_ENROLL_STAT_SIZE, qm_size))
        return EnrollStat(resp[0x16:0x16 + QM_ENROLL_STAT_SIZE]), resp[2:18]

    def enroll_commit(self, tuid : bytes, user_id : bytes = None, identity_type : int = WINBIO_ID_TYPE_SID, timeout : int = 5000) -> bytes:
        #0x96/3: finalize + persist the on-chip template under the given user identity.
        #user_id defaults to the captured Windows SID (reproduces the validated commit);
        #Linux enrollments pass their own identity blob (variable length, see build_enroll_commit).
        assert len(tuid) == 16
        if user_id is None: user_id = WIN_CAPTURED_SID
        req = build_enroll_commit(tuid, user_id, identity_type)
        status, resp = self._send(req, 0x40, timeout)
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        return resp

    def enroll_end(self, timeout : int = 5000) -> bytes:
        #5-byte request: [0x96][u32 sub-op=4] — release the enroll session.
        req = struct.pack("<BI", tudor.Command.MATCHER_ENROLL, ENROLL_END)
        status, resp = self._send(req, 0x100, timeout)
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        return resp

    #--- capture recipe + enroll orchestration ---

    def _send_checked(self, req : bytes, resp_size : int, timeout : int = 2000):
        #raw=False so a non-success status raises (arm commands are expected to succeed).
        return self.sensor.comm.send_command(req, resp_size, timeout)

    def _poll_event(self, eh, want_types, budget_s : float, should_cancel=None):
        #Non-blocking poll of EVENT_READ (0x87) until an event in want_types shows up, or
        #timeout. Avoids the event handler's infinite interrupt-EP block. If should_cancel is
        #given and returns True, aborts by raising CaptureCancelled (checked each iteration).
        deadline = time.time() + budget_s
        while time.time() < deadline:
            if should_cancel is not None and should_cancel():
                raise CaptureCancelled()
            try:
                eh.read_events(block=False)
            except Exception as e:
                logging.log(tudor.LOG_WARN, "  read_events: %r" % e)
            while len(eh.event_queue) > 0:
                e = eh.event_queue.pop(0)
                if e.event_type in want_types:
                    return e
            time.sleep(0.05)
        return None

    def capture_one_frame(self, finger_budget_s : float = 30, frame_budget_s : float = 8, should_cancel=None):
        #Captured Windows recipe: wait FINGER_PRESS -> LED_EX2 cfg -> arm frame event +
        #FRAME_ACQ(17B) -> wait frame-ready (EVENT10=24) -> LED_EX2 cfg -> FRAME_FINISH.
        #Leaves a captured frame on-chip for add_image. Returns the finger event, or None
        #if no finger arrived within finger_budget_s. Raises CaptureCancelled if cancelled.
        eh = self.sensor.event_handler
        eh.set_event_mask([SensorEventType.FINGER_PRESS, SensorEventType.FINGER_REMOVE])
        fp = self._poll_event(eh, [SensorEventType.FINGER_PRESS], finger_budget_s, should_cancel=should_cancel)
        if fp is None:
            eh.set_event_mask([])
            return None
        self._send_checked(LED_EX2_CFG, 2)
        eh.set_event_mask([SensorEventType.EVENT10])          # arm frame-ready (bit 24 / DRDY)
        self._send_checked(FRAME_ACQ_17B, 2)
        fr = self._poll_event(eh, [SensorEventType.EVENT10], frame_budget_s, should_cancel=should_cancel)
        logging.log(tudor.LOG_INFO, "  finger pressed; frame-ready=%s" % ("yes" if fr else "NO"))
        self._send_checked(LED_EX2_CFG, 2)
        self._send_checked(FRAME_FINISH, 2)
        eh.set_event_mask([])
        return fp

    def enroll_loop(self, max_images : int = 25, finger_budget_s : float = 30, on_progress=None, should_cancel=None):
        #Runs enroll_start then [capture_one_frame -> add_image] until progress==100.
        #Returns (final EnrollStat, tuid). Does NOT commit (caller decides).
        self.enroll_start()
        tuid = None
        for i in range(max_images):
            ev = self.capture_one_frame(finger_budget_s=finger_budget_s, should_cancel=should_cancel)
            if ev is None:
                raise TimeoutError("no finger press on image %d" % (i + 1))
            stat, t = self.enroll_add_image()
            if any(t): tuid = t
            if on_progress: on_progress(i, stat, t)
            if stat.complete:
                return stat, (tuid or t)
        raise Exception("enroll did not reach progress==100 within %d images" % max_images)

    #--- identify / verify (opcode 0x99) ---

    def identify(self, template_uids : list = None, timeout : int = 15000):
        #Identify the currently-captured finger. template_uids=None/[] => identify against
        #ALL on-chip templates (nTemplates=0), as Windows does. Returns a MatchResult on a
        #match (with .matched_tuid) or None on no-match (status 0x0509 MATCHER_MATCH_FAILED).
        if template_uids is None: template_uids = []
        for u in template_uids: assert len(u) == 16
        n = len(template_uids)
        req = struct.pack("<BIII", tudor.Command.MATCHER_IDENTIFY, 1, n * 16, 0) + b"".join(template_uids)
        status, resp = self._send(req, 0x400, timeout)
        if status == MATCHER_NO_MATCH:
            return None
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        if len(resp) < 0x1e + QM_MATCH_RESULT_SIZE:
            raise Exception("identify short reply (%d): %s" % (len(resp), resp.hex()))
        matched_tuid = resp[2:18]
        qm_size, = struct.unpack_from("<I", resp, 0x12)
        if qm_size != QM_MATCH_RESULT_SIZE:
            raise Exception("QM match-result size mismatch host=%d sensor=%d" % (QM_MATCH_RESULT_SIZE, qm_size))
        mr = MatchResult(resp[0x1e:0x1e + QM_MATCH_RESULT_SIZE])
        mr.matched_tuid = matched_tuid
        return mr

    def verify(self, finger_budget_s : float = 30, should_cancel=None):
        #Capture one frame (same arm as enroll) then identify against all on-chip templates.
        #Returns MatchResult (on match) or None (no match / no finger). Raises CaptureCancelled.
        ev = self.capture_one_frame(finger_budget_s=finger_budget_s, should_cancel=should_cancel)
        if ev is None:
            return None
        return self.identify()
