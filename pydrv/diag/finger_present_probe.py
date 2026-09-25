"""READ-ONLY diagnostic for the "held / already-present finger not detected" bug.

capture_one_frame() waits for a FINGER_PRESS *edge* via set_event_mask([FINGER_PRESS,
FINGER_REMOVE]) + EVENT_READ. set_event_mask resyncs the host sequence to the sensor's
current sequence (EVENT_CONFIG reply @+64). Hypothesis: a finger already down when the
mask is set produces its FINGER_PRESS at a sequence < the resynced value, so we skip it
and never see the finger (confirmed: holding a finger for 75s => "no finger" every round).

This probe, over ~15s while a finger is HELD, each iteration:
  * sends EVENT_CONFIG([FINGER_PRESS,FINGER_REMOVE]) and records the post-config seq,
  * EVENT_READ from that seq (current driver behavior),
  * EVENT_READ from a few sequences earlier (candidate fix: don't resync past the
    just-triggered event),
  * dumps FRAME_STATE_GET(0x82) in case it carries a finger-present level bit.
Only reads (0x82/0x86/0x87); no capture/enroll/match. Usage: python3 -u diag/finger_present_probe.py
"""
import os, sys, time, struct, traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
import tudor
from tudor.comm import USBCommunication
from tudor.sensor import Sensor, SensorPairingData
from tudor.paths import resolve_pdata

PID = 0x00BC
SEQ_OFF = 64  # EVENT_CONFIG reply (0x42=66B): u16 current seq at offset 64


def event_config(comm, mask_events):
    mask = 0
    for e in mask_events:
        mask |= (1 << e)
    req = struct.pack("<B8II", tudor.Command.EVENT_CONFIG,
                      mask, mask, mask, mask, mask, mask, mask, mask,
                      0 if mask != 0 else 4)
    resp = comm.send_command(req, 0x42)
    seq = struct.unpack_from("<H", resp, SEQ_OFF)[0]
    return seq, resp


def event_read(comm, seq):
    req = struct.pack("<BHHI", tudor.Command.EVENT_READ, seq & 0xffff, 32, 1)
    resp = comm.send_command(req, 390)
    num_evts, num_pending = struct.unpack_from("<HH", resp, 2)
    evts = [resp[6 + i * 12] for i in range(num_evts)]
    return num_evts, num_pending, evts


def frame_state(comm):
    try:
        resp = comm.send_command(struct.pack("<HxxxxxBB", tudor.Command.FRAME_STATE_GET, 2, 7), 0x22)
        return resp.hex()
    except Exception as e:
        return "err:%r" % e


def main():
    dev = usb.core.find(idVendor=0x06CB, idProduct=PID)
    if dev is None:
        print("NO_DEVICE"); return 2
    comm = USBCommunication(dev)
    s = None
    try:
        s = Sensor(comm)
        with open(resolve_pdata(s.id.hex()), "rb") as f:
            s.initialize(SensorPairingData.load(f))
        print("init OK")

        print("--- baseline (NO finger expected) ---")
        seqA, raw = event_config(comm, [])
        print("cfg[] seq=%d" % seqA)
        seqA, raw = event_config(comm, [1, 2])
        n, p, e = event_read(comm, seqA)
        print("cfg[press,rm] seq=%d fromSeq: n=%d pend=%d evts=%s | frame_state=%s"
              % (seqA, n, p, e, frame_state(comm)))

        print("--- NOW HOLD an enrolled finger for the whole loop (~15s) ---")
        for it in range(10):
            seqA, raw = event_config(comm, [1, 2])
            n_cur, p_cur, e_cur = event_read(comm, seqA)
            back = (seqA - 8) & 0xffff
            n_bk, p_bk, e_bk = event_read(comm, back)
            print("it=%2d seqA=%5d cfgtail=%s | fromSeqA: n=%d pend=%d evts=%s | fromSeqA-8(=%d): n=%d pend=%d evts=%s"
                  % (it, seqA, raw[60:66].hex(), n_cur, p_cur, e_cur, back, n_bk, p_bk, e_bk))
            time.sleep(1.5)

        event_config(comm, [])  # disarm
        return 0
    except Exception:
        print("ERR:\n%s" % traceback.format_exc())
        return 1
    finally:
        try:
            if s is not None and s.initialized:
                s.uninitialize()
        except Exception:
            pass
        try:
            comm.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
