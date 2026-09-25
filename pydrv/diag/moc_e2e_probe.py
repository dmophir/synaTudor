"""Phase 2.5 end-to-end validation: label-based enroll -> list -> verify -> (optional) delete.

Exercises exactly the code paths the new drvcmd enroll/verify/templates commands use:
  - SensorMatcher.enroll_loop + enroll_commit(user_id=make_linux_sid(rid)) + enroll_end
  - TemplateStore (host label<->TUID map at /etc/tudor/<id>.templates.json)
  - SensorDB2.iter_templates (walk users -> templates) for listing
  - SensorMatcher.verify -> identify, mapped back to a label
  - SensorDB2.delete_object (0xa3) for cleanup (only with --delete)

This is the on-device proof for the variable-length user-id commit builder: it commits a
freshly enrolled template under a host-synthesized SID (per-label RID) rather than the
captured Windows SID, then confirms verify still matches and maps to the label.

Needs a human to press/lift a finger. Usage (root, from pydrv/):
  python3 -u diag/moc_e2e_probe.py --label linux_test [--verify-rounds 3] [--delete]
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
from tudor.sensor import (Sensor, SensorPairingData, SensorDB2, SensorMatcher,
                          make_linux_sid, WINBIO_ID_TYPE_SID, DB2_CAT_TEMPLATE)
from tudor.driver.drvcmd.tmpl_store import TemplateStore

PID = 0x00BC
from tudor.paths import resolve_pdata
PDATA = resolve_pdata("22eb371d62990000")


def list_templates(db2, store):
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
    ap.add_argument("--label", default="linux_test")
    ap.add_argument("--verify-rounds", type=int, default=3)
    ap.add_argument("--delete", action="store_true", help="delete the enrolled template + prune store at the end")
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
        store = TemplateStore(s.id)
        print("init OK fw %d.%d.%d ; store=%s" % (s.fw_major, s.fw_minor, s.fw_build_num, store.path))

        print(">>> templates BEFORE:")
        before = set(t.hex() for _, t in list_templates(db2, store))

        rid = store.next_rid(args.label)
        user_id = make_linux_sid(rid)
        print(">>> ENROLL label='%s' (rid=%d, sid=%s, type=SID). Press+lift your finger repeatedly..."
              % (args.label, rid, user_id.hex()))

        def on_progress(i, stat, tuid):
            print("    image %d: progress=%d%% quality=%d templateCount=%d rejected=%d"
                  % (i + 1, stat.progress, stat.quality, stat.template_count, stat.rejected))

        try:
            stat, tuid = matcher.enroll_loop(on_progress=on_progress)
            print(">>> progress=100; committing under host SID...")
            matcher.enroll_commit(tuid, user_id=user_id, identity_type=WINBIO_ID_TYPE_SID)
            matcher.enroll_end()
        except BaseException:
            try: matcher.enroll_end()
            except Exception: pass
            try: s.event_handler.set_event_mask([])
            except Exception: pass
            raise
        store.add(tuid, args.label, user_id, WINBIO_ID_TYPE_SID)
        print(">>> ENROLLED '%s' -> TUID %s" % (args.label, tuid.hex()))

        print(">>> templates AFTER:")
        after = set(t.hex() for _, t in list_templates(db2, store))
        new = after - before
        print(">>> VERDICT enroll: %s (new tuids: %s)" % ("PERSISTED" if tuid.hex() in after else "NOT FOUND", new))

        print(">>> VERIFY %d rounds. Press the ENROLLED finger, then a DIFFERENT finger." % args.verify_rounds)
        for r in range(args.verify_rounds):
            print(">>> verify round %d: press a finger..." % (r + 1))
            try:
                mr = matcher.verify(finger_budget_s=30)
            finally:
                try: s.event_handler.set_event_mask([])
                except Exception: pass
            if mr is None:
                print("    round %d: NO MATCH" % (r + 1))
            else:
                lbl = store.label_for(mr.matched_tuid) or "(unmapped)"
                print("    round %d: MATCH label='%s' tuid=%s score=0x%x (%d) templateUpdate=%d"
                      % (r + 1, lbl, mr.matched_tuid.hex(), mr.score, mr.score, mr.template_update))
            time.sleep(0.4)

        if args.delete:
            print(">>> DELETE enrolled template %s ..." % tuid.hex())
            status, deleted = db2.delete_object(DB2_CAT_TEMPLATE, tuid)
            store.remove_tuid(tuid.hex())
            print("    deleted status=0x%04x deleted_objects=%s" % (status, deleted))
            print(">>> templates AFTER DELETE:")
            list_templates(db2, store)
        else:
            print(">>> (kept enrolled template; re-run with --delete to remove it)")
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
            if s is not None and s.initialized: s.uninitialize()
        except Exception:
            pass
        try:
            raw.close()
        except Exception as e:
            print("close_err=%r" % e)


if __name__ == "__main__":
    sys.exit(main())
