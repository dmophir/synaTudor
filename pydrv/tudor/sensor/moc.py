from __future__ import annotations

import struct
import logging
import tudor
from .sensor import *
from tudor.win.tagval import WinTagValContainer

#Match-In-Sensor (MOC) matcher command primitives, RE'd from synaWudfBioUsb103.dll.
#The matcher multiplexes a small VCSFW opcode set by a "QM command struct" in the body:
#  enroll     = opcode 0x96, sub-op u32 at body+0 (START=1, ADD_IMAGE=2, FINISH=4)
#  ident/match= opcode 0x99, misIdentifyMatchCmd
#Request buffer = [opcode:u8][body]; comm.send_command TLS-wraps it. Reply: status at
#resp[:2], QM struct at resp[2:]; size u32 at QM+0x10; enroll stat copied from QM+0x14
#(60 bytes), match result from QM+0x1c (36 bytes). All little-endian.

ENROLL_START = 1
ENROLL_ADD_IMAGE = 2
ENROLL_FINISH = 4

QM_ENROLL_STAT_SIZE = 0x3c   # 60
QM_MATCH_RESULT_SIZE = 0x24  # 36

#mis-layer result codes surfaced by the enroll orchestration
ENROLL_RES_MORE = 305   # 0x131 more images needed
ENROLL_RES_FAIL = 304   # 0x130 failed / fixed-pattern

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

    def enroll_add_image(self, timeout : int = 15000) -> EnrollStat:
        #5-byte request: [0x96][u32 sub-op=2]
        req = struct.pack("<BI", tudor.Command.MATCHER_ENROLL, ENROLL_ADD_IMAGE)
        status, resp = self._send(req, 0x100, timeout)
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        if len(resp) < 0x16 + QM_ENROLL_STAT_SIZE:
            raise Exception("enroll_add_image short reply (%d): %s" % (len(resp), resp.hex()))
        qm_size, = struct.unpack_from("<I", resp, 0x12)
        if qm_size != QM_ENROLL_STAT_SIZE:
            raise Exception("QM enroll-stat size mismatch host=%d sensor=%d (qm struct on host and MFW)" % (QM_ENROLL_STAT_SIZE, qm_size))
        return EnrollStat(resp[0x16:0x16 + QM_ENROLL_STAT_SIZE])

    def enroll_finish(self, timeout : int = 5000) -> bytes:
        #5-byte request: [0x96][u32 sub-op=4]
        req = struct.pack("<BI", tudor.Command.MATCHER_ENROLL, ENROLL_FINISH)
        status, resp = self._send(req, 0x100, timeout)
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        return resp

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
