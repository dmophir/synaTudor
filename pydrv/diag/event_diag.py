"""Phase D5 event diagnostic: what does a finger press produce on 06cb:00bc?

Arms finger events (EVENT_CONFIG mask 1,2), then for ~40s polls EVENT_READ (0x87)
AND the interrupt EP (0x83), logging everything, while the user presses/lifts. Tells
us whether finger/frame events are delivered via the interrupt EP, via EVENT_READ
polling, or both -- so capture_one_frame can wait correctly. Non-destructive (no
FRAME_ACQ). Usage: python3 -u diag/event_diag.py
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
from tudor.comm import USBCommunication, LogCommunicationProxy
from tudor.sensor import Sensor, SensorPairingData, SensorEventType

PID = 0x00BC
from tudor.paths import resolve_pdata
PDATA = resolve_pdata("22eb371d62990000")
DURATION = 40


def main():
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
        eh = s.event_handler
        print("init OK fw %d.%d.%d" % (s.fw_major, s.fw_minor, s.fw_build_num))

        # Arm finger press + remove events (the mask Windows uses for finger detect).
        eh.set_event_mask([SensorEventType.FINGER_PRESS, SensorEventType.FINGER_REMOVE])
        print(">>> armed finger events; PRESS and LIFT your finger repeatedly for %ds..." % DURATION)

        deadline = time.time() + DURATION
        last_intr = None
        while time.time() < deadline:
            # 1) non-blocking interrupt EP peek
            buf = array.array('B', [0] * 8)
            try:
                n = raw.intr_ep.read(buf, 200)
                ev = bytes(buf[:n])
                if ev != last_intr:
                    print("  INTR: %s" % ev.hex())
                    last_intr = ev
            except usb.core.USBTimeoutError:
                pass
            # 2) non-blocking EVENT_READ poll
            try:
                n = eh.read_events(block=False)
                if n:
                    while eh.event_queue:
                        e = eh.event_queue.pop(0)
                        print("  EVENT_READ -> %r" % e)
            except Exception as e:
                print("  read_events err: %r" % e)
            time.sleep(0.1)

        eh.set_event_mask([])
        print(">>> done")
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
