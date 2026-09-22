"""Phase D5 diagnostic: on-chip ENROLL via the captured Windows recipe.

Per-image recipe (from wincapture ground truth): LED_EX2 config (0x39) -> EVENT_CONFIG
frame-arm -> FRAME_ACQ (17B production) -> wait finger-press frame latch -> LED_EX2 ->
FRAME_FINISH -> add_image (0x96/2). Loop to progress==100, then commit (0x96/3) + end
(0x96/4). This replaces the earlier attempt that crashed (it lacked the 0x39 config and
used the 25B diagnostic FRAME_ACQ).

Creates an on-chip template (reversible via DB2_DELETE_OBJ 0xa3). Needs the user to
press/lift a finger several times. Usage (root, from pydrv/):
  python3 -u diag/enroll_probe.py [--no-commit]
"""
import os
import sys
import time
import struct
import logging
import argparse
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
PER_IMAGE_BUDGET = 45


def snapshot_templates(db2):
    info = db2.get_db_info()
    status, entries, _ = db2.list_objects(DB2_CAT_TEMPLATE)
    return info.num_current_templates, [e.hex() for e in entries]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-commit", action="store_true", help="stop after progress==100, do not commit")
    args = ap.parse_args()

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
    s = None
    try:
        s = Sensor(comm)
        with open(PDATA, "rb") as f:
            pdata = SensorPairingData.load(f)
        s.initialize(pdata)
        db2 = SensorDB2(s)
        matcher = SensorMatcher(s)
        print("init OK: fw %d.%d.%d" % (s.fw_major, s.fw_minor, s.fw_build_num))

        before_count, before_uids = snapshot_templates(db2)
        print(">>> templates BEFORE: count=%d uids=%s" % (before_count, before_uids))

        def on_progress(i, stat, tuid):
            print(">>> image %d: %r tuid=%s" % (i + 1, stat, tuid.hex() if any(tuid) else "(pending)"))

        print(">>> ENROLL START — press and lift your finger repeatedly when prompted...")
        print(">>> (press for image 1 now)")
        stat, tuid = matcher.enroll_loop(max_images=MAX_IMAGES, finger_budget_s=PER_IMAGE_BUDGET, on_progress=on_progress)
        print(">>> ENROLL LOOP COMPLETE: progress=100, tuid=%s templateCount=%d" % (tuid.hex(), stat.template_count))

        if args.no_commit:
            print(">>> --no-commit: stopping before commit (per request)")
        else:
            print(">>> commit (0x96/3) ..."); matcher.enroll_commit(tuid)
            print(">>> end (0x96/4) ...");    matcher.enroll_end()
            print(">>> commit+end OK")

        after_count, after_uids = snapshot_templates(db2)
        print(">>> templates AFTER: count=%d uids=%s" % (after_count, after_uids))
        new = [u for u in after_uids if u not in before_uids]
        if after_count > before_count or new:
            print(">>> VERDICT: template PERSISTED on-chip (count %d->%d, new=%s)" % (before_count, after_count, new))
        else:
            print(">>> VERDICT: no new DB2 template (count still %d)" % after_count)
        return 0
    except tudor.CommandFailedException as e:
        print(">>> COMMAND FAILED status=0x%04x" % e.status)
        print(traceback.format_exc())
        return 1
    except Exception:
        print("ERR:\n%s" % traceback.format_exc())
        return 1
    finally:
        try:
            if s is not None and s.initialized:
                comm.send_command(struct.pack("<B", tudor.Command.FRAME_FINISH), 2, raw=True)
        except Exception:
            pass
        try:
            if s is not None: s.uninitialize()
        except Exception:
            pass
        try:
            raw.close()
        except Exception as e:
            print("close_err=%r" % e)


if __name__ == "__main__":
    sys.exit(main())
