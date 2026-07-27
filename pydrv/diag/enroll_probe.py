"""Phase C3 diagnostic: on-chip ENROLL + auto-persist check (WRITES sensor state).

Drives the MOC enroll state machine over the established TLS channel:
  enroll_start (0x96/1) -> loop[ wait FINGER_PRESS -> add_image (0x96/2) -> read
  60-byte stat ] until progress==100 -> enroll_finish (0x96/4).

Then re-lists DB2 templates (category 2) before/after to answer the KEY question:
does the sensor AUTO-PERSIST the enrolled template to flash (count 0 -> 1), or must
the host WRITE_OBJECT it (the pEncryptedTemplate branch)?

This creates an on-chip template (reversible later via DB2_DELETE_OBJ 0xa3). It needs
the user to physically press/lift a finger on the tablet sensor several times.

Usage (root, from pydrv/, user at the sensor): python diag/enroll_probe.py
"""
import os
import sys
import time
import struct
import logging
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
import tudor
from tudor.comm import USBCommunication, LogCommunicationProxy, SUCCESS_STATUS
from tudor.sensor import (Sensor, SensorPairingData, SensorDB2, SensorMatcher,
                          SensorEventType, DB2_CAT_TEMPLATE)

PID = 0x00BC
PDATA = "/etc/tudor/22eb371d62990000.pdata"
OUT = "/root/synatudor/phaseC/enroll"
MAX_IMAGES = 25


def snapshot_templates(db2):
    info = db2.get_db_info()
    status, entries, _ = db2.list_objects(DB2_CAT_TEMPLATE)
    return info.num_current_templates, [e.hex() for e in entries]


def main():
    os.makedirs(OUT, exist_ok=True)
    for lvl, nm in [(tudor.LOG_COMM, "COMM"), (tudor.LOG_PROTO, "PROTO"), (tudor.LOG_TLS, "TLS"),
                    (tudor.LOG_DETAIL, "DETAIL"), (tudor.LOG_INFO, "INFO"), (tudor.LOG_WARN, "WARN")]:
        logging.addLevelName(lvl, nm)
    logging.basicConfig(level=tudor.LOG_COMM, format="%(levelname)6s %(message)s",
                        handlers=[logging.FileHandler(os.path.join(OUT, "enroll_probe.log"), mode="w"),
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
        db2 = SensorDB2(s)
        matcher = SensorMatcher(s)
        print("init OK: fw %d.%d.%d" % (s.fw_major, s.fw_minor, s.fw_build_num))

        before_count, before_uids = snapshot_templates(db2)
        print(">>> templates BEFORE enroll: count=%d uids=%s" % (before_count, before_uids))

        print(">>> enroll_start")
        matcher.enroll_start(nonce_present=0, nonce=0)

        completed = False
        for i in range(MAX_IMAGES):
            print(">>> image %d/%d: PRESS and HOLD your finger on the sensor..." % (i + 1, MAX_IMAGES))
            try:
                s.event_handler.wait_for_event([SensorEventType.FINGER_PRESS])
            except KeyboardInterrupt:
                print("interrupted while waiting for press"); break

            try:
                stat = matcher.enroll_add_image(timeout=8000)
                print("    %r" % stat)
            except usb.core.USBTimeoutError:
                print("    add_image TIMED OUT (no reply) — add_image may not be a blocking/self-capture cmd")
                break
            except tudor.CommandFailedException as e:
                print("    add_image FAILED status=0x%04x" % e.status)
                # 0x131(305)=more images (continue), 0x130(304)=fail
                if e.status == 0x130:
                    print("    -> enroll failed (fixed-pattern / bad)"); break
                stat = None

            if stat is not None and stat.complete:
                print("    ENROLL COMPLETE (progress=100, templateCount=%d)" % stat.template_count)
                completed = True

            print(">>> lift your finger...")
            try:
                s.event_handler.wait_for_event([SensorEventType.FINGER_REMOVE])
            except KeyboardInterrupt:
                pass
            if completed:
                break
            time.sleep(0.3)

        print(">>> enroll_finish")
        try:
            fin = matcher.enroll_finish()
            print("    finish resp head=%s" % fin[:16].hex())
        except Exception as e:
            print("    enroll_finish: %r" % e)

        after_count, after_uids = snapshot_templates(db2)
        print(">>> templates AFTER enroll: count=%d uids=%s" % (after_count, after_uids))
        new_uids = [u for u in after_uids if u not in before_uids]
        if after_count > before_count or new_uids:
            print(">>> VERDICT: sensor AUTO-PERSISTED template (count %d->%d, new=%s) — no host WRITE_OBJECT needed"
                  % (before_count, after_count, new_uids))
            for uidhex in new_uids:
                uid = bytes.fromhex(uidhex)
                istatus, iinfo = db2.get_object_info(DB2_CAT_TEMPLATE, uid)
                dstatus, ddata, _ = db2.get_object_data(DB2_CAT_TEMPLATE, uid)
                print("    new template uid=%s info(0x%04x,len=%d) data(0x%04x,len=%d)"
                      % (uidhex, istatus, len(iinfo), dstatus, len(ddata)))
                if len(ddata) > 0:
                    with open(os.path.join(OUT, "template_%s.bin" % uidhex), "wb") as f:
                        f.write(ddata)
        else:
            print(">>> VERDICT: NO new DB2 template (count still %d) — host WRITE_OBJECT/pEncryptedTemplate likely required (C5)"
                  % after_count)

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
