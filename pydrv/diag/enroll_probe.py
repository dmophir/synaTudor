"""Phase C3 diagnostic (v2): on-chip ENROLL with per-image FRAME_ACQ arm.

Correction after v1 crashed the sensor: misEnrollAddImage (0x96/2) does NOT capture;
it consumes a frame the sensor already latched on-chip. RE of the production capture
(vfmUtilCaptureImage -> tudorCaptureStart) shows the arm is EVENT_CONFIG(0x86, DRDY
bit24) + FRAME_ACQ(0x80, mode3), then wait frame-ready on the interrupt EP; NO
FRAME_READ(0x7f). Those exact arm bytes are the ones capture.py already uses and the
sensor accepts. So per image we: arm -> wait latched frame -> misEnrollAddImage(0x96/2).

Then re-list DB2 templates (cat 2) before/after -> auto-persist verdict.

Creates an on-chip template (reversible via DB2_DELETE_OBJ 0xa3). Needs the user to
press/lift a finger several times. Usage (root, from pydrv/): python diag/enroll_probe.py
"""
import os
import sys
import time
import array
import struct
import logging
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
import tudor
from tudor.comm import USBCommunication, LogCommunicationProxy, SUCCESS_STATUS
from tudor.sensor import Sensor, SensorPairingData, SensorDB2, SensorMatcher, DB2_CAT_TEMPLATE

PID = 0x00BC
PDATA = "/etc/tudor/22eb371d62990000.pdata"
OUT = "/root/synatudor/phaseC/enroll"
MAX_IMAGES = 25

# Validated arm bytes (from capture.py, accepted by the sensor):
EVENT_CONFIG_DRDY = struct.pack("<B4I4II", tudor.Command.EVENT_CONFIG,
                                0x01000000, 0, 0, 0, 0x01000000, 0, 0, 0, 1)
FRAME_ACQ_MODE3 = (struct.pack("<B", tudor.Command.FRAME_ACQ) + struct.pack("<I", 1) + struct.pack("<I", 1)
                   + bytes([0x01, 0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00,
                            0x01, 0x00, 0x00, 0x0c, 0x14, 0x00, 0x02, 0x00]))


def arm_and_wait_frame(comm, raw, budget_s=25):
    """Arm a single on-chip frame capture and wait (bounded) until it latches on a
    finger press. Reads the interrupt EP directly with a 1s timeout so a no-press
    can't hang. Returns the interrupt report on success, or None on timeout."""
    comm.send_command(EVENT_CONFIG_DRDY, 0x42)
    comm.send_command(FRAME_ACQ_MODE3, 2)
    deadline = time.time() + budget_s
    while time.time() < deadline:
        buf = array.array('B', [0] * 8)
        try:
            n = raw.intr_ep.read(buf, 1000)
        except usb.core.USBTimeoutError:
            continue
        ev = bytes(buf[:n])
        if len(ev) >= 6 and ev[0] == 2 and (ev[5] & 0x7) != 0:
            return ev
    return None


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
        total_deadline = time.time() + 200
        for i in range(MAX_IMAGES):
            remaining = total_deadline - time.time()
            if remaining < 5:
                print(">>> global time budget exhausted"); break
            print(">>> image %d/%d: PRESS your finger (arming frame)..." % (i + 1, MAX_IMAGES))
            try:
                ev = arm_and_wait_frame(comm, raw, budget_s=min(90, remaining))
            except tudor.CommandFailedException as e:
                print("    arm FAILED status=0x%04x" % e.status); break
            if ev is None:
                print("    no frame latched (timed out waiting for press)"); break
            print("    frame latched: %s" % ev.hex())

            try:
                stat = matcher.enroll_add_image(timeout=8000)
                print("    %r" % stat)
            except usb.core.USBError as e:
                print("    add_image USB error (sensor reset?): %r" % e); break
            except tudor.CommandFailedException as e:
                print("    add_image FAILED status=0x%04x" % e.status)
                if e.status == 0x130:
                    print("    -> enroll failed (fixed-pattern / bad)"); break
                stat = None

            if stat is not None and stat.complete:
                print("    ENROLL COMPLETE (progress=100, templateCount=%d)" % stat.template_count)
                completed = True
                break
            print(">>> lift your finger...")
            time.sleep(1.5)

        print(">>> enroll_finish")
        try:
            fin = matcher.enroll_finish()
            print("    finish resp head=%s" % fin[:16].hex())
        except Exception as e:
            print("    enroll_finish: %r" % e)

        # best-effort end the capture session
        try:
            comm.send_command(struct.pack("<B", tudor.Command.FRAME_FINISH), 2)
        except Exception:
            pass

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
