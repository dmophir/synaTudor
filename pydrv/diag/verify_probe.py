"""Phase D5.4 diagnostic: on-chip VERIFY / identify (0x99) against enrolled templates.

Captures a frame (same recipe as enroll) then identifies against ALL on-chip templates
(0x99, nTemplates=0). Prints matched TUID + score, or NO MATCH (status 0x0509). Run
several rounds pressing the ENROLLED finger, then a DIFFERENT finger, to see the score
separation and pick a threshold. Usage: python3 -u diag/verify_probe.py [--rounds N]
"""
import os
import sys
import time
import argparse
import logging
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
import tudor
from tudor.comm import USBCommunication, LogCommunicationProxy
from tudor.sensor import Sensor, SensorPairingData, SensorDB2, SensorMatcher, DB2_CAT_TEMPLATE

from tudor.paths import resolve_pdata
PID = 0x00BC
PDATA = resolve_pdata("22eb371d62990000")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=5)
    args = ap.parse_args()

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
        matcher = SensorMatcher(s)
        info = db2.get_db_info()
        print("init OK fw %d.%d.%d ; on-chip templates=%d" % (s.fw_major, s.fw_minor, s.fw_build_num, info.num_current_templates))
        if info.num_current_templates == 0:
            print("WARNING: no templates enrolled — run enroll_probe first")

        print(">>> %d verify rounds. Press the ENROLLED finger first, then try a DIFFERENT finger." % args.rounds)
        for r in range(args.rounds):
            print(">>> round %d: press a finger..." % (r + 1))
            try:
                mr = matcher.verify(finger_budget_s=30)
            except tudor.CommandFailedException as e:
                print("    round %d: identify FAILED status=0x%04x" % (r + 1, e.status)); continue
            if mr is None:
                print("    round %d: NO MATCH" % (r + 1))
            else:
                print("    round %d: MATCH score=0x%x (%d) tuid=%s templateUpdate=%d"
                      % (r + 1, mr.score, mr.score, mr.matched_tuid.hex() if mr.matched_tuid else "?", mr.template_update))
            time.sleep(0.5)
        return 0
    except Exception:
        print("ERR:\n%s" % traceback.format_exc())
        return 1
    finally:
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
