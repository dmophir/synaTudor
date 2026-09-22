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

#--- Per-image capture recipe, byte-for-byte from the Windows enroll capture (2026-09-22).
#0x39 (LED_EX2) sensor/IPL config pushed around each capture. Leading u32 (here 0x3e8) is a
#param/counter; the record tail is static. This is the piece our earlier attempt omitted.
LED_EX2_CFG = bytes.fromhex("39e80300004b000000078c00208c8c000000000000000000004b000000010000200000000000000000000000004b000000018c00200000000000000000000000004b0000000100002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
#FRAME_ACQ production 17-byte form (NOT the 25-byte diagnostic mode-3 that crashed us).
FRAME_ACQ_17B = bytes.fromhex("800c000000010000000100000801010100")
FRAME_FINISH = bytes([0x81])   # 0x81 = FRAME_FINISH

#enroll_commit (0x96/3) captured template; TUID substituted at send time. The 28-byte
#Windows SID is kept as an opaque identity blob (parameterize later for Linux users).
_COMMIT_TEMPLATE = bytes.fromhex("9603000000000000006f000000000010000000160c87f6c0a157979e419e99492af0ef01004c000000030000001c000000010500000000000515000000619fb3c507285b02c10f762de903000000000000000000000000000000000000000000000000000000000000000000000000000000000000020001000000f7")
_COMMIT_CAPTURED_TUID = bytes.fromhex("160c87f6c0a157979e419e99492af0ef")

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

    def enroll_commit(self, tuid : bytes, timeout : int = 5000) -> bytes:
        #0x96/3: finalize + persist the on-chip template. Replays the captured 124-byte
        #commit with our enrolled TUID substituted (identity blob kept as-is for now).
        assert len(tuid) == 16
        req = _COMMIT_TEMPLATE.replace(_COMMIT_CAPTURED_TUID, tuid)
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

    def _poll_event(self, eh, want_types, budget_s : float):
        #Non-blocking poll of EVENT_READ (0x87) until an event in want_types shows up, or
        #timeout. Avoids the event handler's infinite interrupt-EP block.
        deadline = time.time() + budget_s
        while time.time() < deadline:
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

    def capture_one_frame(self, finger_budget_s : float = 30, frame_budget_s : float = 8):
        #Captured Windows recipe: wait FINGER_PRESS -> LED_EX2 cfg -> arm frame event +
        #FRAME_ACQ(17B) -> wait frame-ready (EVENT10=24) -> LED_EX2 cfg -> FRAME_FINISH.
        #Leaves a captured frame on-chip for add_image. Returns the finger event, or None
        #if no finger arrived within finger_budget_s.
        eh = self.sensor.event_handler
        eh.set_event_mask([SensorEventType.FINGER_PRESS, SensorEventType.FINGER_REMOVE])
        fp = self._poll_event(eh, [SensorEventType.FINGER_PRESS], finger_budget_s)
        if fp is None:
            eh.set_event_mask([])
            return None
        self._send_checked(LED_EX2_CFG, 2)
        eh.set_event_mask([SensorEventType.EVENT10])          # arm frame-ready (bit 24 / DRDY)
        self._send_checked(FRAME_ACQ_17B, 2)
        fr = self._poll_event(eh, [SensorEventType.EVENT10], frame_budget_s)
        logging.log(tudor.LOG_INFO, "  finger pressed; frame-ready=%s" % ("yes" if fr else "NO"))
        self._send_checked(LED_EX2_CFG, 2)
        self._send_checked(FRAME_FINISH, 2)
        eh.set_event_mask([])
        return fp

    def enroll_loop(self, max_images : int = 25, finger_budget_s : float = 30, on_progress=None):
        #Runs enroll_start then [capture_one_frame -> add_image] until progress==100.
        #Returns (final EnrollStat, tuid). Does NOT commit (caller decides).
        self.enroll_start()
        tuid = None
        for i in range(max_images):
            ev = self.capture_one_frame(finger_budget_s=finger_budget_s)
            if ev is None:
                raise TimeoutError("no finger press on image %d" % (i + 1))
            stat, t = self.enroll_add_image()
            if any(t): tuid = t
            if on_progress: on_progress(i, stat, t)
            if stat.complete:
                return stat, (tuid or t)
        raise Exception("enroll did not reach progress==100 within %d images" % max_images)

    #--- identify / verify (opcode 0x99) ---

    def identify_match(self, template_uids : list, timeout : int = 15000) -> MatchResult:
        #request: [0x99][u32 const=1][u32 list_len=n*16][u32 blob_len=0][n x 16-byte UID refs]
        for u in template_uids: assert len(u) == 16
        n = len(template_uids)
        payload = b"".join(template_uids)
        req = struct.pack("<BIII", tudor.Command.MATCHER_IDENTIFY, 1, n * 16, 0) + payload
        status, resp = self._send(req, 0x400, timeout)
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        if len(resp) < 0x1e + QM_MATCH_RESULT_SIZE:
            raise Exception("identify_match short reply (%d): %s" % (len(resp), resp.hex()))
        qm_size, auxA_len, auxB_len = struct.unpack_from("<III", resp, 0x12)
        if qm_size != QM_MATCH_RESULT_SIZE:
            raise Exception("QM match-result size mismatch host=%d sensor=%d" % (QM_MATCH_RESULT_SIZE, qm_size))
        off = 0x1e
        result = resp[off:off + QM_MATCH_RESULT_SIZE]; off += QM_MATCH_RESULT_SIZE
        auxA = resp[off:off + auxA_len]; off += auxA_len
        auxB = resp[off:off + auxB_len]
        return MatchResult(result, auxA, auxB)
