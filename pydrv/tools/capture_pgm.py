"""Headless pair + capture-to-PGM tool for Synaptics Tudor/Augusta sensors.

Purpose: validate the rev image pipeline on 06cb:00bc without matplotlib/X —
capture raw frames over TLS, reconstruct via libnative (IPL), and write PGM
files that can be scp'd back and inspected.

!!! NOT READ-ONLY !!!
  --pair takes ownership of the sensor (PAIR/0x93). This RE-KEYS the sensor and
  BREAKS any existing enrollment made under another OS (e.g. Windows). It is
  gated behind an explicit flag and further behind --yes. Without --pair /
  --capture this tool does nothing to sensor state.

Typical use:
  # 1c (destructive): take ownership + persist pairing data
  sudo python tools/capture_pgm.py --pair --yes --pdata /etc/tudor/pdata.tpd --fprintd-setup
  # 1d: capture N images and write PGMs
  sudo python tools/capture_pgm.py --capture 3 --pdata /etc/tudor/pdata.tpd --out /root/caps
"""
import os
import sys
import argparse
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
import tudor
import tudor.sensor
from tudor.comm import USBCommunication
from tudor.sensor import Sensor, SensorPairingData, SensorEventType


def write_pgm(path, img):
    w, h = img.width, img.height
    buf = bytearray(w * h)
    for y in range(h):
        base = y * w
        for x in range(w):
            buf[base + x] = img[x, y] & 0xFF
    with open(path, "wb") as f:
        f.write(b"P5\n%d %d\n255\n" % (w, h))
        f.write(buf)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=lambda x: int(x, 0), default=0x00BC)
    ap.add_argument("--pdata", required=True, help="pairing-data file path")
    ap.add_argument("--pair", action="store_true", help="DESTRUCTIVE: take ownership and save pairing data")
    ap.add_argument("--yes", action="store_true", help="confirm the destructive --pair")
    ap.add_argument("--fprintd-setup", action="store_true", help="also write /etc/tudor/<id>.pdata")
    ap.add_argument("--capture", type=int, default=0, help="capture N images and write PGMs")
    ap.add_argument("--out", default=".", help="output dir for PGMs")
    args = ap.parse_args()

    if args.pair and not args.yes:
        print("REFUSING: --pair is destructive (breaks Windows enrollment). Re-run with --yes.")
        return 3
    if not args.pair and args.capture <= 0:
        print("Nothing to do: pass --pair and/or --capture N.")
        return 0

    dev = usb.core.find(idVendor=0x06CB, idProduct=args.pid)
    if dev is None:
        print("NO_DEVICE for 06cb:%04x" % args.pid)
        return 2
    print("found 06cb:%04x bus=%d addr=%d" % (args.pid, dev.bus, dev.address))

    comm = USBCommunication(dev)
    try:
        s = Sensor(comm)
        print("sensor fw=%d.%d.%d id=%s prov=%s" % (s.fw_major, s.fw_minor, s.fw_build_num, s.id.hex(), s.prov_state))

        if args.pair:
            print("PAIRING (take ownership) ...")
            pdata = s.pair()
            with open(args.pdata, "wb") as f:
                pdata.save(f)
            print("saved pairing data -> %s" % args.pdata)
            if args.fprintd_setup:
                os.makedirs("/etc/tudor", exist_ok=True)
                os.chmod("/etc/tudor", 0o700)
                p = "/etc/tudor/%s.pdata" % s.id.hex()
                with open(p, "wb") as f:
                    pdata.save(f)
                print("fprintd pairing data -> %s" % p)

        if args.capture > 0:
            with open(args.pdata, "rb") as f:
                pdata = SensorPairingData.load(f)
            print("initializing (TLS) ...")
            s.initialize(pdata)
            print("in_tls=%s" % (s.tls_session is not None))

            print("Lift finger off the sensor ...")
            s.event_handler.wait_for_event([SensorEventType.FINGER_REMOVE])
            print("Now PRESS and hold your finger on the sensor ...")
            images = s.frame_capturer.capture_images(args.capture)

            os.makedirs(args.out, exist_ok=True)
            for i, img in enumerate(images):
                path = os.path.join(args.out, "cap_%02d.pgm" % i)
                write_pgm(path, img)
                print("image %d: %dx%d enough_coverage=%s -> %s"
                      % (i, img.width, img.height, img.enough_coverage, path))

            s.uninitialize()
    except Exception:
        print("ERR:\n%s" % traceback.format_exc())
        return 1
    finally:
        try:
            comm.close()
        except Exception as e:
            print("close_err=%r" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
