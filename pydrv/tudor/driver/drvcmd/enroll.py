from .cmd import *
from .context import *

import tudor.sensor

@cmd("enroll")
class CmdEnroll(Command):
    """
    Enrolls a fingerprint on-chip (match-in-sensor) under a label.
    Loops finger presses until progress reaches 100%, commits the template with a
    host-derived user identity, and records the label<->TUID mapping.
    Usage: enroll <label>
    """

    def run(self, ctx : CmdContext, args : list):
        if not ctx.sensor.initialized: raise Exception("Sensor isn't initialized!")
        if len(args) <= 0: raise Exception("No label given! Usage: enroll <label>")
        label = " ".join(args).strip()

        store = ctx.template_store()
        th, rec = store.find_label(label)
        if rec is not None:
            if input("Label '%s' already maps to TUID %s. Enroll another finger for it? (y/n): " % (label, th)).strip().lower() != "y":
                return

        matcher = tudor.sensor.SensorMatcher(ctx.sensor)

        #Derive a unique, well-formed SID identity for this label (proven identity_type=3).
        rid = store.next_rid(label)
        user_id = tudor.sensor.make_linux_sid(rid)
        identity_type = tudor.sensor.WINBIO_ID_TYPE_SID

        def on_progress(i, stat, tuid):
            print("  image %d: progress=%d%% quality=%d templateCount=%d rejected=%d"
                  % (i + 1, stat.progress, stat.quality, stat.template_count, stat.rejected))

        print("Enroll '%s': press and lift your finger repeatedly when prompted (need progress 100%%)..." % label)
        try:
            stat, tuid = matcher.enroll_loop(on_progress=on_progress)
            print("Capture complete (progress=100). Committing template under label '%s'..." % label)
            matcher.enroll_commit(tuid, user_id=user_id, identity_type=identity_type)
            matcher.enroll_end()
        except BaseException:
            #Best-effort release of the on-chip enroll session so a failed run doesn't
            #leave the matcher half-open (which can wedge the sensor).
            try: matcher.enroll_end()
            except Exception: pass
            try: ctx.sensor.event_handler.set_event_mask([])
            except Exception: pass
            raise

        store.add(tuid, label, user_id, identity_type)
        print("Enrolled '%s' -> TUID %s (host mapping saved to %s)" % (label, tuid.hex(), store.path))
