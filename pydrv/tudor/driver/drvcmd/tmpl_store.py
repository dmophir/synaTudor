from __future__ import annotations

import os
import json
import time
import hashlib
import struct

#Host-side template registry. The sensor matches on-chip and, on a successful verify,
#returns the matched template's 16-byte TUID -- but not a human-meaningful identity. This
#store persists the mapping label <-> TUID (plus the user-id blob we committed) so the
#driver can (a) name enrolled fingers, (b) map a verify result back to a label, and
#(c) enumerate/delete by label. It is host state only; the sensor's DB2 objects remain
#authoritative for what is actually enrolled.
#
#File: /etc/tudor/<sensor-id>.templates.json (0600). Schema:
#  {"version":1, "sensor_id":"<hex>", "templates": {
#      "<tuid_hex>": {"label":..., "user_id":"<hex>", "identity_type":int, "enrolled_at":epoch}}}

STORE_DIR = "/etc/tudor"
STORE_VERSION = 1


class TemplateStore:
    def __init__(self, sensor_id : bytes):
        self.sensor_id = sensor_id.hex() if isinstance(sensor_id, (bytes, bytearray)) else str(sensor_id)
        self.templates = {}   #tuid_hex -> record dict
        self.load()

    @property
    def path(self):
        return os.path.join(STORE_DIR, "%s.templates.json" % self.sensor_id)

    def load(self):
        self.templates = {}
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.templates = data.get("templates", {}) or {}
        except Exception:
            #Corrupt/old file -> start clean rather than crash the CLI.
            self.templates = {}

    def save(self):
        if not os.path.exists(STORE_DIR):
            os.makedirs(STORE_DIR)
            os.chmod(STORE_DIR, 0o700)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"version": STORE_VERSION, "sensor_id": self.sensor_id, "templates": self.templates}, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    #--- mutation ---

    def add(self, tuid : bytes, label : str, user_id : bytes, identity_type : int):
        self.templates[tuid.hex()] = {
            "label": label,
            "user_id": user_id.hex(),
            "identity_type": int(identity_type),
            "enrolled_at": int(time.time()),
        }
        self.save()

    def remove_tuid(self, tuid_hex : str) -> bool:
        if tuid_hex in self.templates:
            del self.templates[tuid_hex]
            self.save()
            return True
        return False

    #--- lookup ---

    def by_tuid(self, tuid):
        return self.templates.get(tuid.hex() if isinstance(tuid, (bytes, bytearray)) else tuid)

    def label_for(self, tuid):
        rec = self.by_tuid(tuid)
        return rec["label"] if rec else None

    def find_label(self, label : str):
        for th, rec in self.templates.items():
            if rec.get("label") == label:
                return th, rec
        return None, None

    def items(self):
        return list(self.templates.items())

    def labels(self):
        return [rec.get("label") for rec in self.templates.values()]

    #--- identity policy ---

    def next_rid(self, label : str) -> int:
        """Derives a stable 32-bit RID for a label (used to synthesize a unique SID).
        Deterministic from the label so re-enrolling the same label reuses the same user;
        collisions are astronomically unlikely for the small label counts in practice."""
        h = hashlib.sha256(label.encode("utf-8")).digest()
        rid = struct.unpack_from("<I", h, 0)[0]
        #keep it in a plausible RID range (>=1000), avoid 0.
        return 1000 + (rid % 0x7fff0000)
