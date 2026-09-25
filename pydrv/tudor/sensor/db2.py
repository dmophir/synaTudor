from __future__ import annotations

import struct
import logging
import tudor
from .sensor import *

#DB2 object "category" selector passed in the request (per RE of synaWudfBioUsb103.dll).
#GET_DB_INFO returns per-category counts in the order users/templates/payloads, so the
#category selector is assumed 1=user, 2=template, 3=payload. The object TYPE TAG stored
#inside a template object is 0x20 (used by CEisMisEIV::RetrieveTemplatesFromFlash's filter
#`cmp [entry], 0x20`). These are different notions; the probe dumps raw to confirm.
DB2_CAT_USER = 1
DB2_CAT_TEMPLATE = 2
DB2_CAT_PAYLOAD = 3

OBJ_TAG_TEMPLATE = 0x20

class DB2Info:
    #Parsed VCSFW_CMD_DB2_GET_DB_INFO (0x9e) response payload (38 bytes, LE), offsets per RE.
    def __init__(self, payload : bytes):
        (self.dummy, self.ver_major, self.ver_minor, self.pversion,
         self.uop_len, self.top_len, self.pop_len,
         self.tmpl_slot_size, self.pay_slot_size,
         self.num_current_users, self.num_deleted_users, self.num_avail_user_slots,
         self.num_current_templates, self.num_deleted_templates, self.num_avail_tmpl_slots,
         self.num_current_payloads, self.num_deleted_payloads, self.num_avail_pay_slots
         ) = struct.unpack_from("<HHHIHHHHHHHHHHHHHH", payload, 0)

    def __repr__(self):
        return ("DB2Info(pversion=%d ver=%d.%d users=%d/%d/%d templates=%d/%d/%d payloads=%d/%d/%d "
                "tmplSlot=%d paySlot=%d)" % (
                    self.pversion, self.ver_major, self.ver_minor,
                    self.num_current_users, self.num_deleted_users, self.num_avail_user_slots,
                    self.num_current_templates, self.num_deleted_templates, self.num_avail_tmpl_slots,
                    self.num_current_payloads, self.num_deleted_payloads, self.num_avail_pay_slots,
                    self.tmpl_slot_size, self.pay_slot_size))

class SensorDB2:
    """DB2 on-sensor object storage (read path). All requests: [opcode:u8][body]; TLS-wrapped
    by comm.send_command. Responses: status at resp[:2], payload at resp[2:]. Uses raw=True so a
    non-success status is returned (not raised) for diagnostic visibility."""

    def __init__(self, sensor : Sensor):
        self.sensor = sensor

    def _cmd(self, req : bytes, resp_size : int, timeout : int = 2000):
        resp = self.sensor.comm.send_command(req, resp_size, timeout, raw=True)
        status = struct.unpack("<H", resp[:2])[0] if len(resp) >= 2 else -1
        return status, resp

    def get_db_info(self) -> DB2Info:
        req = struct.pack("<BB", tudor.Command.DB2_GET_DB_INFO, 1)
        status, resp = self._cmd(req, 0x40)
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        if len(resp) < 2 + 38: raise Exception("DB2_GET_DB_INFO short response: %s" % resp.hex())
        return DB2Info(resp[2:])

    def list_objects(self, category : int, key : bytes = None):
        """Low-level GET_OBJECT_LIST (0x9f). Returns (status, entries, raw_payload).
        Request body = category(u8)+3pad+16B key. Response payload framing (confirmed
        on-device): u16 count, then count x 16-byte UID entries.

        NOTE the DB2 object hierarchy (confirmed on-device 2026-09-22): USER objects
        (category 1) are top-level and listed with a ZERO key; TEMPLATE (2) and PAYLOAD
        (3) objects are enumerated PER-USER -- the 16-byte key must be the parent user's
        UID, not zero. Listing templates with a zero key returns count=0 even when
        GET_DB_INFO reports templates present. Prefer the list_users/list_templates/
        iter_templates helpers below over calling this directly."""
        if key is None: key = bytes(16)
        assert len(key) == 16
        req = struct.pack("<BB", tudor.Command.DB2_GET_OBJ_LIST, category) + bytes(3) + key
        status, resp = self._cmd(req, 0x800)
        payload = resp[2:] if len(resp) >= 2 else b""
        entries = []
        if status in tudor.SUCCESS_STATUS and len(payload) >= 2:
            count = struct.unpack_from("<H", payload, 0)[0]
            body = payload[2:]
            entries = [body[i*16:(i+1)*16] for i in range(count) if (i+1)*16 <= len(body)]
        return status, entries, payload

    def list_users(self):
        """Returns the list of 16-byte USER UIDs (top-level; zero key)."""
        status, entries, _ = self.list_objects(DB2_CAT_USER, bytes(16))
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        return entries

    def list_templates(self, user_uid : bytes):
        """Returns the 16-byte TEMPLATE UIDs (TUIDs) belonging to the given user."""
        assert len(user_uid) == 16
        status, entries, _ = self.list_objects(DB2_CAT_TEMPLATE, user_uid)
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        return entries

    def iter_templates(self):
        """Walks every user and yields (user_uid, tuid) for each on-chip template.
        This is the correct way to enumerate all enrolled templates (see list_objects
        note): first list users, then list templates under each user."""
        for user_uid in self.list_users():
            for tuid in self.list_templates(user_uid):
                yield user_uid, tuid

    def all_template_uids(self):
        """Convenience: flat list of every TUID currently on-chip."""
        return [tuid for _, tuid in self.iter_templates()]

    def delete_object(self, category : int, uid : bytes):
        """DB2_DELETE_OBJ (0xa3). Reversible-in-spirit destructive op on a single object;
        body = category(u8) + 3pad + 16B uid (wire = op + 20-byte body). Verified against
        the 103 builder fcn.1800aea50 (category at body[0], uid memcpy'd at body[4] => 3 pad;
        the same framing as GET_OBJECT_INFO/DATA). Returns (status, deleted_objects).
        Used to remove an enrolled template (category 2). NOT format -- targets one UID."""
        assert len(uid) == 16
        req = struct.pack("<BB", tudor.Command.DB2_DELETE_OBJ, category) + bytes(3) + uid
        status, resp = self._cmd(req, 0x40)
        if status not in tudor.SUCCESS_STATUS: raise tudor.CommandFailedException(status)
        deleted = struct.unpack_from("<H", resp, 2)[0] if len(resp) >= 4 else None
        return status, deleted

    def delete_template(self, tuid : bytes, prune_empty_user : bool = True):
        """Deletes an enrolled template by TUID (category 2), and -- if prune_empty_user --
        also removes the parent user object once it has no remaining templates, so we don't
        leak DB2 user slots on repeated enroll/delete cycles. Uses only the validated
        0xa3 DELETE_OBJECT framing (same builder for user/template categories); this is the
        safe, RE-grounded alternative to the (still unpinned) 0xa4 CLEANUP compaction op.
        Returns (tmpl_status, tmpl_deleted, pruned_user_uid_or_None). NOT a format."""
        assert len(tuid) == 16
        #Locate the parent user (needed both to prune and because listing is per-user).
        parent = None
        for user_uid, t in self.iter_templates():
            if t == tuid:
                parent = user_uid
                break
        tmpl_status, tmpl_deleted = self.delete_object(DB2_CAT_TEMPLATE, tuid)
        pruned = None
        if prune_empty_user and parent is not None:
            try:
                if len(self.list_templates(parent)) == 0:
                    self.delete_object(DB2_CAT_USER, parent)
                    pruned = parent
            except tudor.CommandFailedException as e:
                logging.log(tudor.LOG_WARN, "delete_template: parent-user prune failed status=0x%04x" % e.status)
        return tmpl_status, tmpl_deleted, pruned

    def get_object_info(self, category : int, uid : bytes):
        assert len(uid) == 16
        req = struct.pack("<BB", tudor.Command.DB2_GET_OBJ_INFO, category) + bytes(3) + uid
        status, resp = self._cmd(req, 0x100)
        return status, resp[2:] if len(resp) >= 2 else b""

    def get_object_data(self, category : int, uid : bytes, max_size : int = 0x4000):
        """Returns (status, payload). Per RE the response is [status:2][?:2][datalen:u32 @+4]
        [payload @+8]. We slice payload using the +4 length when the response is long enough."""
        assert len(uid) == 16
        req = struct.pack("<BB", tudor.Command.DB2_GET_OBJ_DATA, category) + bytes(3) + uid
        status, resp = self._cmd(req, max_size)
        data = b""
        if status in tudor.SUCCESS_STATUS and len(resp) >= 8:
            datalen = struct.unpack_from("<I", resp, 4)[0]
            data = resp[8:8+datalen] if datalen <= len(resp) - 8 else resp[8:]
        return status, data, resp
