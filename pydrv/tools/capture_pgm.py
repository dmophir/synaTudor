"""Headless pair + capture-to-PGM tool for Synaptics Tudor/Augusta sensors.

Purpose: validate the rev image pipeline on 06cb:00bc without matplotlib/X —
capture raw frames over TLS, save them, reconstruct via libnative (IPL), and
write PGM files (+ per-image stats) that can be scp'd back and inspected.

!!! --pair IS NOT READ-ONLY !!!
  --pair takes ownership of the sensor (PAIR/0x93), re-keying it and BREAKING any
  existing Windows enrollment. Gated behind --pair + --yes. --capture is
  non-destructive (only reads frames); it loads existing pairing data.

Typical use:
  # 1d: capture N images (needs a finger on the sensor); save raw + PGM + stats
  python tools/capture_pgm.py --capture 5 --pdata /etc/tudor/<id>.pdata --out /root/synatudor/1d
"""
import os
import sys
import io
import signal
import logging
import argparse
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
import tudor
from tudor.comm import USBCommunication, LogCommunicationProxy
from tudor.sensor import Sensor, SensorPairingData, SensorEventType


def setup_logging(logpath):
    for lvl, name in [(tudor.LOG_COMM, "COMM"), (tudor.LOG_PROTO, "PROTO"),
                      (tudor.LOG_TLS, "TLS"), (tudor.LOG_DETAIL, "DETAIL"),
                      (tudor.LOG_INFO, "INFO"), (tudor.LOG_WARN, "WARN")]:
        logging.addLevelName(lvl, name)
    logging.basicConfig(level=tudor.LOG_COMM,
                        format="%(levelname)7s  %(message)s",
                        handlers=[logging.FileHandler(logpath, mode="w"),
                                  logging.StreamHandler(sys.stderr)])


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


def img_stats(img):
    vals = [img[x, y] for x in range(img.width) for y in range(img.height)]
    n = len(vals)
    mn, mx = min(vals), max(vals)
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n
    return mn, mx, mean, var ** 0.5


class _Timeout(Exception):
    pass


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=lambda x: int(x, 0), default=0x00BC)
    ap.add_argument("--pdata", required=True)
    ap.add_argument("--pair", action="store_true", help="DESTRUCTIVE: take ownership")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--fprintd-setup", action="store_true")
    ap.add_argument("--capture", type=int, default=0, help="capture N images")
    ap.add_argument("--out", default=".", help="output dir")
    ap.add_argument("--timeout", type=int, default=60, help="overall capture timeout (s)")
    args = ap.parse_args()

    if args.pair and not args.yes:
        print("REFUSING: --pair is destructive. Re-run with --yes.")
        return 3
    if not args.pair and args.capture <= 0:
        print("Nothing to do: pass --pair and/or --capture N.")
        return 0

    os.makedirs(args.out, exist_ok=True)
    setup_logging(os.path.join(args.out, "1d_capture.log"))

    dev = usb.core.find(idVendor=0x06CB, idProduct=args.pid)
    if dev is None:
        print("NO_DEVICE for 06cb:%04x" % args.pid)
        return 2
    print("found 06cb:%04x bus=%d addr=%d" % (args.pid, dev.bus, dev.address))

    raw = USBCommunication(dev)
    comm = LogCommunicationProxy(raw)
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
            print("in_tls=%s  frame=%dx%d pixel_bits=%d frame_size=%d"
                  % (s.tls_session is not None, s.frame_capturer.width, s.frame_capturer.height,
                     s.frame_capturer.pixel_bits, s.frame_capturer.frame_size))

            print(">>> Lift finger off the sensor ...")
            s.event_handler.wait_for_event([SensorEventType.FINGER_REMOVE])
            print(">>> Now PRESS and HOLD your finger on the sensor (capturing %d frames) ..." % args.capture)

            signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(_Timeout()))
            signal.alarm(args.timeout)
            try:
                frames = s.frame_capturer.capture_frames(args.capture)
            finally:
                signal.alarm(0)
            print("captured %d raw frames" % len(frames))

            # Save raw frames + meta first (so reconstruction failure doesn't lose data)
            meta = os.path.join(args.out, "meta.txt")
            with open(meta, "w") as m:
                m.write("id=%s fw=%d.%d.%d\n" % (s.id.hex(), s.fw_major, s.fw_minor, s.fw_build_num))
                m.write("frame=%dx%d pixel_bits=%d frame_size=%d frame_header=%d col_header=%d stride=%d\n"
                        % (s.frame_capturer.width, s.frame_capturer.height, s.frame_capturer.pixel_bits,
                           s.frame_capturer.frame_size, s.frame_capturer.frame_header_size,
                           s.frame_capturer.col_header_size, s.frame_capturer.frame_stride))
                m.write("cfg_ver=%d.%d.%d ipl_iota_len=%d\n" % (s.cfg_ver.major, s.cfg_ver.minor, s.cfg_ver.revision, len(s.ipl_iota.payload)))
                m.write("ipl_iota=%s\n" % s.ipl_iota.payload.hex())
            for i, fr in enumerate(frames):
                with open(os.path.join(args.out, "frame_%02d.bin" % i), "wb") as f:
                    f.write(fr)
            print("saved raw frames + meta -> %s" % args.out)

            # Reconstruct via libnative IPL
            for i, fr in enumerate(frames):
                try:
                    img = s.frame_capturer.frame_to_image(fr)
                    pgm = os.path.join(args.out, "cap_%02d.pgm" % i)
                    write_pgm(pgm, img)
                    mn, mx, mean, sd = img_stats(img)
                    print("image %d: %dx%d coverage=%s  px[min=%d max=%d mean=%.1f std=%.1f] -> %s"
                          % (i, img.width, img.height, img.enough_coverage, mn, mx, mean, sd, pgm))
                except Exception:
                    print("reconstruct frame %d FAILED (raw saved):\n%s" % (i, traceback.format_exc()))

            s.uninitialize()
    except _Timeout:
        print("CAPTURE TIMEOUT after %ds (no/insufficient frames?). Check 1d_capture.log." % args.timeout)
        return 4
    except Exception:
        print("ERR:\n%s" % traceback.format_exc())
        return 1
    finally:
        try:
            raw.close()
        except Exception as e:
            print("close_err=%r" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
