from .cmd import *
from .context import *

import tudor.sensor

@cmd("verify")
class CmdVerify(Command):
    """
    Captures a finger and identifies it against ALL on-chip templates (match-in-sensor).
    Prints the matched label + score, or NO MATCH.
    Usage: verify
    """

    def run(self, ctx : CmdContext, args : list):
        if not ctx.sensor.initialized: raise Exception("Sensor isn't initialized!")
        store = ctx.template_store()
        matcher = tudor.sensor.SensorMatcher(ctx.sensor)

        print("Press a finger to verify...")
        try:
            mr = matcher.verify(finger_budget_s=30)
        finally:
            try: ctx.sensor.event_handler.set_event_mask([])
            except Exception: pass

        if mr is None:
            print("NO MATCH (no enrolled template matched, or no finger detected)")
            return
        label = store.label_for(mr.matched_tuid)
        who = ("'%s'" % label) if label else "(unmapped TUID -- not in host store)"
        print("MATCH: label=%s tuid=%s score=0x%x (%d) templateUpdate=%d"
              % (who, mr.matched_tuid.hex(), mr.score, mr.score, mr.template_update))


@cmd("identify")
class CmdIdentify(CmdVerify):
    """Alias for verify (identify against all on-chip templates). Usage: identify"""
    pass
