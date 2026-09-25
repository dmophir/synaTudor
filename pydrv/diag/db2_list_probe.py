"""Phase C1b diagnostic (READ-ONLY): resolve DB2 template enumeration.

GET_DB_INFO reports 1 user / 1 template / 1 payload, but GET_OBJECT_LIST for
categories 2/3 with a zero key returns 0 entries, while category 1 returns the
user UID. Hypothesis: templates (cat 2) and payloads (cat 3) are enumerated
PER-USER -- the 16-byte request key is the parent user UID, not zero.

This probe lists users (cat 1, zero key), then for each user UID re-lists cat 2
and cat 3 using that UID as the key, and dumps object info/data for whatever it
finds. Read-only: only 0x9e/0x9f/0xa0/0xa1. Usage: python3 -u diag/db2_list_probe.py
"""
import os
import sys
import struct
import logging
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
import tudor
from tudor.comm import USBCommunication, LogCommunicationProxy, SUCCESS_STATUS
from tudor.sensor import Sensor, SensorPairingData, SensorDB2, DB2_CAT_USER, DB2_CAT_TEMPLATE, DB2_CAT_PAYLOAD

PID = 0x00BC
from tudor.paths import resolve_pdata
PDATA = resolve_pdata("22eb371d62990000")


def hexdump(b, n=96):
    return b[:n].hex() + ("..." if len(b) > n else "")


def raw_list(db2, cat, key):
    req = struct.pack("<BB", tudor.Command.DB2_GET_OBJ_LIST, cat) + bytes(3) + key
    status, resp = db2._cmd(req, 0x800)
    return status, resp[2:] if len(resp) >= 2 else b""


def show(db2, cat, key, label):
    status, payload = raw_list(db2, cat, key)
    print("  LIST cat=%d key=%s (%s) status=0x%04x len=%d raw=%s"
          % (cat, key.hex(), label, status, len(payload), hexdump(payload)))
    entries = []
    if status in SUCCESS_STATUS and len(payload) >= 2:
        count = struct.unpack_from("<H", payload, 0)[0]
        body = payload[2:]
        entries = [body[i*16:(i+1)*16] for i in range(count) if (i+1)*16 <= len(body)]
        for i, e in enumerate(entries):
            print("      entry[%d]=%s" % (i, e.hex()))
    return entries


def main():
    logging.basicConfig(level=tudor.LOG_WARN, format="%(levelname)6s %(message)s",
                        handlers=[logging.StreamHandler(sys.stderr)])
    dev = usb.core.find(idVendor=0x06CB, idProduct=PID)
    if dev is None:
        print("NO_DEVICE"); return 2
    raw = USBCommunication(dev)
    comm = LogCommunicationProxy(raw)
    s = None
    try:
        s = Sensor(comm)
        with open(PDATA, "rb") as f:
            pdata = SensorPairingData.load(f)
        s.initialize(pdata)
        db2 = SensorDB2(s)
        info = db2.get_db_info()
        print("init OK; %r" % info)

        print(">>> users (cat 1, zero key):")
        users = show(db2, DB2_CAT_USER, bytes(16), "users")

        for u in users:
            print(">>> templates/payloads under user %s:" % u.hex())
            tmpls = show(db2, DB2_CAT_TEMPLATE, u, "templates@user")
            pays = show(db2, DB2_CAT_PAYLOAD, u, "payloads@user")
            for t in tmpls:
                istatus, iinfo = db2.get_object_info(DB2_CAT_TEMPLATE, t)
                dstatus, ddata, draw = db2.get_object_data(DB2_CAT_TEMPLATE, t)
                print("    TMPL %s info st=0x%04x len=%d head=%s | data st=0x%04x len=%d head=%s"
                      % (t.hex(), istatus, len(iinfo), hexdump(iinfo, 48),
                         dstatus, len(ddata), hexdump(ddata, 48)))

        print(">>> also try template/payload list with zero key (baseline):")
        show(db2, DB2_CAT_TEMPLATE, bytes(16), "templates@zero")
        show(db2, DB2_CAT_PAYLOAD, bytes(16), "payloads@zero")
        return 0
    except Exception:
        print("ERR:\n%s" % traceback.format_exc())
        return 1
    finally:
        try:
            if s is not None and s.initialized: s.uninitialize()
        except Exception:
            pass
        try:
            raw.close()
        except Exception as e:
            print("close_err=%r" % e)


if __name__ == "__main__":
    sys.exit(main())
