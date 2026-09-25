"""Phase 2.5 helper (no finger needed): list or delete on-chip templates.

Mirrors the `templates` REPL command over the same SensorDB2 + TemplateStore calls, for
non-interactive validation of the enumeration (item a) and delete (0xa3) paths.

Usage (root, from pydrv/):
  python3 -u diag/templates_probe.py list
  python3 -u diag/templates_probe.py delete <label|tuidhex>
"""
import os
import sys
import argparse
import logging
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
import tudor
from tudor.comm import USBCommunication, LogCommunicationProxy
from tudor.sensor import Sensor, SensorPairingData, SensorDB2, DB2_CAT_TEMPLATE
from tudor.driver.drvcmd.tmpl_store import TemplateStore

PID = 0x00BC
from tudor.paths import resolve_pdata
PDATA = resolve_pdata("22eb371d62990000")


def show(db2, store):
    info = db2.get_db_info()
    print("  on-chip DB2: users=%d templates=%d payloads=%d"
          % (info.num_current_users, info.num_current_templates, info.num_current_payloads))
    pairs = list(db2.iter_templates())
    for user_uid, tuid in pairs:
        rec = store.by_tuid(tuid)
        lbl = ("'%s'" % rec["label"]) if rec else "(unmapped)"
        print("    tuid=%s user=%s label=%s" % (tuid.hex(), user_uid.hex(), lbl))
    return pairs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["list", "delete"])
    ap.add_argument("target", nargs="?", default=None)
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
        store = TemplateStore(s.id)
        print(">>> templates:")
        pairs = show(db2, store)

        if args.action == "delete":
            if not args.target:
                print("delete needs <label|tuidhex>"); return 2
            match = None
            for user_uid, tuid in pairs:
                if tuid.hex() == args.target.lower():
                    match = (user_uid, tuid); break
            if match is None:
                th, rec = store.find_label(args.target)
                if th is not None:
                    for user_uid, tuid in pairs:
                        if tuid.hex() == th:
                            match = (user_uid, tuid); break
            if match is None:
                print("no on-chip template for '%s'" % args.target); return 1
            user_uid, tuid = match
            status, deleted = db2.delete_object(DB2_CAT_TEMPLATE, tuid)
            store.remove_tuid(tuid.hex())
            print(">>> deleted tuid=%s status=0x%04x deleted_objects=%s" % (tuid.hex(), status, deleted))
            print(">>> templates AFTER delete:")
            show(db2, store)
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
