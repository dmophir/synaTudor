from .cmd import *
from .context import *

import tudor.sensor

@cmd("templates")
class CmdTemplates(Command):
    """
    Lists or deletes on-chip enrolled templates (match-in-sensor).
    Enumerates DB2 objects on the sensor (users -> templates) and cross-references the
    host label store. Delete targets a template by label or TUID (hex).
    Usage: templates list
           templates delete <label|tuid>
    """

    def run(self, ctx : CmdContext, args : list):
        if not ctx.sensor.initialized: raise Exception("Sensor isn't initialized!")
        if len(args) <= 0: raise Exception("Usage: templates list | templates delete <label|tuid>")
        sub = args[0].lower()
        db2 = tudor.sensor.SensorDB2(ctx.sensor)
        store = ctx.template_store()

        if sub == "list":
            info = db2.get_db_info()
            print("on-chip DB2: users=%d templates=%d payloads=%d (tmplSlot=%d)"
                  % (info.num_current_users, info.num_current_templates, info.num_current_payloads, info.tmpl_slot_size))
            pairs = list(db2.iter_templates())
            onchip = set()
            if not pairs:
                print("  (no templates on-chip)")
            for user_uid, tuid in pairs:
                onchip.add(tuid.hex())
                rec = store.by_tuid(tuid)
                label = ("'%s'" % rec["label"]) if rec else "(unmapped)"
                print("  tuid=%s  user=%s  label=%s" % (tuid.hex(), user_uid.hex(), label))
            for th, rec in store.items():
                if th not in onchip:
                    print("  [stale host entry, not on-chip] tuid=%s label='%s'" % (th, rec.get("label")))

        elif sub == "delete":
            if len(args) < 2: raise Exception("Usage: templates delete <label|tuid>")
            target = " ".join(args[1:]).strip()
            pairs = list(db2.iter_templates())

            match = None
            for user_uid, tuid in pairs:
                if tuid.hex() == target.lower():
                    match = (user_uid, tuid); break
            if match is None:
                th, rec = store.find_label(target)
                if th is not None:
                    for user_uid, tuid in pairs:
                        if tuid.hex() == th:
                            match = (user_uid, tuid); break
                    if match is None:
                        print("Label '%s' has no on-chip template; pruning stale host entry." % target)
                        store.remove_tuid(th)
                        return
            if match is None:
                raise Exception("No template found for '%s' (not a known TUID or label). Try 'templates list'." % target)

            user_uid, tuid = match
            lbl = store.label_for(tuid) or "?"
            if input("Delete on-chip template tuid=%s (label='%s')? (y/n): " % (tuid.hex(), lbl)).strip().lower() != "y":
                return
            status, deleted = db2.delete_object(tudor.sensor.DB2_CAT_TEMPLATE, tuid)
            store.remove_tuid(tuid.hex())
            print("Deleted on-chip (status=0x%04x, deleted_objects=%s); host mapping pruned." % (status, deleted))

        else:
            raise Exception("Unknown subcommand '%s'. Usage: templates list | templates delete <label|tuid>" % sub)
