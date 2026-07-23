"""Phase 1d diagnostic: after ONE finger press, sweep FRAME_READ seq values.

Static RE says FRAME_ACQ(mode3) is accepted, seq=0 is correct, and readiness
(interrupt[0]==2) is met — yet FRAME_READ(seq=0) returns 0x0689. This probe
resolves it empirically in a single press: it arms capture, waits for a latched
frame, then tries FRAME_READ for seq 0..7 (raw, no exceptions) and logs the
status + response length for each, stopping at the first success.

Non-destructive (capture only reads frames; no pairing/storage change).
Usage (root, from pydrv/): python diag/frame_read_probe.py
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
from tudor.sensor import Sensor, SensorPairingData, SensorEventType

PID = 0x00BC
PDATA = "/etc/tudor/22eb371d62990000.pdata"
OUT = "/root/synatudor/1d/probe"


def main():
    os.makedirs(OUT, exist_ok=True)
    for lvl, nm in [(tudor.LOG_COMM, "COMM"), (tudor.LOG_PROTO, "PROTO"), (tudor.LOG_TLS, "TLS"),
                    (tudor.LOG_DETAIL, "DETAIL"), (tudor.LOG_INFO, "INFO"), (tudor.LOG_WARN, "WARN")]:
        logging.addLevelName(lvl, nm)
    logging.basicConfig(level=tudor.LOG_PROTO, format="%(levelname)6s %(message)s",
                        handlers=[logging.FileHandler(os.path.join(OUT, "probe.log"), mode="w"),
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
        fc = s.frame_capturer
        print("init OK: frame=%dx%d frame_size=%d" % (fc.width, fc.height, fc.frame_size))

        print(">>> Lift finger ...")
        s.event_handler.wait_for_event([SensorEventType.FINGER_REMOVE])
        print(">>> PRESS and HOLD finger now ...")

        # Arm capture: mode-3 FRAME_ACQ, num_frames=1
        frame_acq = (struct.pack("<B", tudor.Command.FRAME_ACQ) + struct.pack("<I", 1) + struct.pack("<I", 1)
                     + bytes([0x01, 0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00,
                              0x01, 0x00, 0x00, 0x0c, 0x14, 0x00, 0x02, 0x00]))
        r = comm.send_command(frame_acq, 2, raw=True)
        print("FRAME_ACQ status=0x%04x" % struct.unpack("<H", r[:2])[0])

        # Poll interrupt EP until a frame is latched (interrupt[0]==2 and index!=0), or timeout
        ready = None
        for i in range(100):
            ev = comm.get_event_data()
            print("  ev[%02d]=%s (b0=%d b5=%d)" % (i, ev.hex(), ev[0], ev[5] & 0x7))
            if ev[0] == 2 and (ev[5] & 0x7) != 0:
                ready = ev
                break
            time.sleep(0.05)
        print("readiness: %s" % (ready.hex() if ready else "TIMED OUT"))

        # Sweep FRAME_READ seq 0..7 (raw so we see the status instead of raising)
        for seq in range(8):
            req = struct.pack("<BHxxHH", tudor.Command.FRAME_READ, seq, 0xffff, 3)
            resp = comm.send_command(req, 8 + fc.frame_size, raw=True)
            st = struct.unpack("<H", resp[:2])[0]
            print("FRAME_READ seq=%d -> status=0x%04x resp_len=%d head=%s"
                  % (seq, st, len(resp), resp[:12].hex()))
            if st in SUCCESS_STATUS and len(resp) > 8:
                path = os.path.join(OUT, "frame_seq%d.bin" % seq)
                with open(path, "wb") as f:
                    f.write(resp[8:8 + fc.frame_size])
                print("  >>> SUCCESS seq=%d: saved %d frame bytes -> %s" % (seq, len(resp) - 8, path))
                break
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
