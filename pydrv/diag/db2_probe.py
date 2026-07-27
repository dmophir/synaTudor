"""Phase C1 diagnostic (READ-ONLY): enumerate on-chip DB2 objects.

00bc is a match-on-chip sensor; enrolled fingerprint templates persist as DB2
objects (object type tag 0x20). This probe validates the DB2 read layer on-device
and dumps the current object inventory, WITHOUT writing anything:
  - GET_DB_INFO (0x9e)                -> per-category counts
  - GET_OBJECT_LIST (0x9f) x cat 1..3 -> raw entries (16-byte UIDs)
  - GET_OBJECT_INFO (0xa0) / GET_OBJECT_DATA (0xa1) per listed UID -> sizes + head

Non-destructive: only DB2 read opcodes (0x9e/0x9f/0xa0/0xa1). No WRITE/DELETE/FORMAT.
Usage (root, from pydrv/): python diag/db2_probe.py
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
PDATA = "/etc/tudor/22eb371d62990000.pdata"
OUT = "/root/synatudor/phaseC/db2"


def hexdump(b, n=64):
    return b[:n].hex() + ("..." if len(b) > n else "")


def dump_list(db2, cat, name):
    status, entries, payload = db2.list_objects(cat)
    print("  LIST cat=%d(%s) status=0x%04x payload_len=%d count=%d"
          % (cat, name, status, len(payload), len(entries)))
    print("    raw: %s" % hexdump(payload, 96))
    for i, e in enumerate(entries):
        print("    entry[%d]: %s" % (i, e.hex()))
    return entries


def main():
    os.makedirs(OUT, exist_ok=True)
    for lvl, nm in [(tudor.LOG_COMM, "COMM"), (tudor.LOG_PROTO, "PROTO"), (tudor.LOG_TLS, "TLS"),
                    (tudor.LOG_DETAIL, "DETAIL"), (tudor.LOG_INFO, "INFO"), (tudor.LOG_WARN, "WARN")]:
        logging.addLevelName(lvl, nm)
    logging.basicConfig(level=tudor.LOG_COMM, format="%(levelname)6s %(message)s",
                        handlers=[logging.FileHandler(os.path.join(OUT, "db2_probe.log"), mode="w"),
                                  logging.StreamHandler(sys.stderr)])

    dev = usb.core.find(idVendor=0x06CB, idProduct=PID)
    if dev is None:
        print("NO_DEVICE"); return 2
    raw = USBCommunication(dev)
    comm = LogCommunicationProxy(raw)
    try:
        s = Sensor(comm)
        with open(PDATA, "rb") as f:
            pdata = SensorPairingData.load(f)
        s.initialize(pdata)
        print("init OK: fw %d.%d.%d product_id=%r" % (s.fw_major, s.fw_minor, s.fw_build_num, s.product_id))

        db2 = SensorDB2(s)

        print(">>> GET_DB_INFO")
        try:
            info = db2.get_db_info()
            print("  %r" % info)
        except Exception as e:
            print("  GET_DB_INFO failed: %r" % e)

        print(">>> GET_OBJECT_LIST (categories 1..3)")
        all_entries = {}
        for cat, name in [(DB2_CAT_USER, "user"), (DB2_CAT_TEMPLATE, "template"), (DB2_CAT_PAYLOAD, "payload")]:
            try:
                all_entries[cat] = dump_list(db2, cat, name)
            except Exception as e:
                print("  LIST cat=%d failed: %r" % (cat, e))

        print(">>> GET_OBJECT_INFO / GET_OBJECT_DATA per listed UID")
        for cat, entries in all_entries.items():
            for i, uid in enumerate(entries):
                try:
                    istatus, iinfo = db2.get_object_info(cat, uid)
                    print("  INFO  cat=%d uid=%s status=0x%04x len=%d head=%s"
                          % (cat, uid.hex(), istatus, len(iinfo), hexdump(iinfo, 48)))
                    dstatus, ddata, draw = db2.get_object_data(cat, uid)
                    print("  DATA  cat=%d uid=%s status=0x%04x data_len=%d head=%s"
                          % (cat, uid.hex(), dstatus, len(ddata), hexdump(ddata, 48)))
                    if dstatus in SUCCESS_STATUS and len(ddata) > 0:
                        path = os.path.join(OUT, "obj_cat%d_%s.bin" % (cat, uid.hex()))
                        with open(path, "wb") as f:
                            f.write(ddata)
                        print("        saved %d bytes -> %s" % (len(ddata), path))
                except Exception as e:
                    print("  obj cat=%d uid=%s failed: %r" % (cat, uid.hex(), e))

        try:
            s.uninitialize()
        except Exception:
            pass
        return 0
    except Exception:
        print("ERR:\n%s" % traceback.format_exc())
        return 1
    finally:
        try:
            raw.close()
        except Exception as e:
            print("close_err=%r" % e)


if __name__ == "__main__":
    sys.exit(main())
