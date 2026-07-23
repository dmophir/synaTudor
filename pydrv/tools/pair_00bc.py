"""Phase 1c: controlled pairing + TLS validation for 06cb:00bc (Augusta).

Two subcommands:

  pair       !!! DESTRUCTIVE !!! Takes ownership of the sensor (PAIR/0x93),
             re-keying it and BREAKING any existing Windows enrollment. Gated
             behind --yes. Ordering is chosen so credentials are saved BEFORE and
             AROUND the single destructive command, so we can never end up
             "paired but without usable pairing data":
               1. save the freshly generated host private key first
               2. send PAIR with raw=True and immediately dump the raw response
               3. only then parse + persist the full pairing data
             All sensor I/O is logged (COMM/TLS/PROTO) to <workdir>/1c_pair.log.

  init-test  Non-destructive: load saved pairing data and run initialize()
             (device-cert verify + TLS 1.2 handshake + frame dims), report, then
             uninitialize(). Repeatable; a failure here costs nothing.

Never prints secrets (host private key / pairing-data bytes) — only paths, sizes,
status codes, and non-secret identifiers.

Usage (root, from pydrv/):
  python tools/pair_00bc.py pair --yes
  python tools/pair_00bc.py init-test
"""
import os
import sys
import io
import struct
import logging
import argparse
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
import cryptography.hazmat.primitives.asymmetric.ec as ecc
import tudor
from tudor.comm import USBCommunication, LogCommunicationProxy, Command, SUCCESS_STATUS
from tudor.sensor import Sensor, SensorCertificate, SensorPairingData

VID = 0x06CB
PID = 0x00BC
WORKDIR = "/root/synatudor/1c"


def setup_logging(logpath):
    logging.addLevelName(tudor.LOG_COMM, "COMM")
    logging.addLevelName(tudor.LOG_PROTO, "PROTO")
    logging.addLevelName(tudor.LOG_TLS, "TLS")
    logging.addLevelName(tudor.LOG_DETAIL, "DETAIL")
    logging.addLevelName(tudor.LOG_INFO, "INFO")
    logging.addLevelName(tudor.LOG_WARN, "WARN")
    logging.basicConfig(level=tudor.LOG_TLS,
                        format="%(levelname)7s  %(message)s",
                        handlers=[logging.FileHandler(logpath, mode="w"),
                                  logging.StreamHandler(sys.stderr)])


def open_sensor():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("NO_DEVICE for %04x:%04x" % (VID, PID))
        sys.exit(2)
    print("found %04x:%04x bus=%d addr=%d" % (VID, PID, dev.bus, dev.address))
    raw = USBCommunication(dev)
    comm = LogCommunicationProxy(raw)
    sensor = Sensor(comm)
    return raw, sensor


def do_pair(args):
    os.makedirs(WORKDIR, exist_ok=True)
    setup_logging(os.path.join(WORKDIR, "1c_pair.log"))

    if not args.yes:
        print("REFUSING: 'pair' is destructive (breaks Windows enrollment). Re-run with --yes.")
        return 3

    raw, sensor = open_sensor()
    try:
        sid = sensor.id.hex()
        print("sensor id=%s fw=%d.%d.%d prov=%s adv_sec=%s key_flag=%s"
              % (sid, sensor.fw_major, sensor.fw_minor, sensor.fw_build_num,
                 sensor.prov_state, sensor.advanced_security, sensor.key_flag))

        if int(sensor.prov_state) != 3:
            print("ABORT: prov_state != 3 (got %s)" % sensor.prov_state)
            return 4
        if not sensor.advanced_security:
            print("ABORT: advanced_security not present")
            return 4

        priv = ecc.generate_private_key(ecc.SECP256R1())
        priv_path = os.path.join(WORKDIR, "hostpriv_%s.bin" % sid)
        with open(priv_path, "wb") as f:
            f.write(priv.private_numbers().private_value.to_bytes(0x44, "little"))
        os.chmod(priv_path, 0o600)
        print("saved host private key -> %s (BEFORE sending PAIR)" % priv_path)

        host_cert = SensorCertificate.create_host_cert(priv.public_key())
        print("built host cert (%d bytes); sending PAIR (0x93) ..." % len(host_cert.tobytes()))

        resp = sensor.comm.send_command(
            struct.pack("<B", Command.PAIR) + host_cert.tobytes(), 0x322, raw=True)

        resp_path = os.path.join(WORKDIR, "pair_resp_%s.bin" % sid)
        with open(resp_path, "wb") as f:
            f.write(resp)
        print("dumped raw PAIR response -> %s (%d bytes)" % (resp_path, len(resp)))

        status = struct.unpack("<H", resp[:2])[0]
        if status not in SUCCESS_STATUS:
            print("PAIR FAILED: status=0x%04x (host cert rejected). STOPPING; not retrying." % status)
            print("Windows binding expected intact. Raw response saved for analysis.")
            return 5
        if len(resp) < 802:
            print("PAIR response too short: %d bytes (need 802). STOPPING." % len(resp))
            return 5

        new_host_cert = SensorCertificate.frombytes(resp[2:402])
        dev_cert = SensorCertificate.frombytes(resp[402:802])
        pdata = SensorPairingData(priv, new_host_cert, dev_cert)

        buf = io.BytesIO()
        pdata.save(buf)
        blob = buf.getvalue()

        os.makedirs("/etc/tudor", exist_ok=True)
        os.chmod("/etc/tudor", 0o700)
        fprintd_path = "/etc/tudor/%s.pdata" % sid
        with open(fprintd_path, "wb") as f:
            f.write(blob)
        os.chmod(fprintd_path, 0o600)
        backup_path = os.path.join(WORKDIR, "pdata_%s.tpd" % sid)
        with open(backup_path, "wb") as f:
            f.write(blob)
        os.chmod(backup_path, 0o600)

        print("PAIR OK: status=0x%04x, dev_cert type=%d" % (status, dev_cert.cert_type))
        print("saved pairing data (%d bytes) -> %s (+ backup %s)" % (len(blob), fprintd_path, backup_path))
        print("PAIRED. Windows enrollment is now BROKEN (recoverable by re-enrolling under Windows).")
        return 0
    except Exception:
        print("PAIR ERROR:\n%s" % traceback.format_exc())
        print("If PAIR was already sent, reconstruct pdata from hostpriv + pair_resp; do NOT re-pair blindly.")
        return 1
    finally:
        try:
            raw.close()
        except Exception as e:
            print("close_err=%r" % e)


def do_init_test(args):
    os.makedirs(WORKDIR, exist_ok=True)
    setup_logging(os.path.join(WORKDIR, "1c_init.log"))

    raw, sensor = open_sensor()
    try:
        sid = sensor.id.hex()
        pdata_path = args.pdata or ("/etc/tudor/%s.pdata" % sid)
        with open(pdata_path, "rb") as f:
            pdata = SensorPairingData.load(f)
        print("loaded pairing data <- %s" % pdata_path)

        sensor.initialize(pdata)
        print("INIT OK: in_tls=%s initialized=%s" % (sensor.tls_session is not None, sensor.initialized))
        fc = sensor.frame_capturer
        print("frame: %dx%d pixel_bits=%d (x_off=%d x_size=%d y_off=%d y_size=%d)"
              % (fc.width, fc.height, fc.pixel_bits, fc.x_off, fc.x_size, fc.y_off, fc.y_size))
        sensor.uninitialize()
        print("uninitialized cleanly")
        return 0
    except Exception:
        print("INIT ERROR:\n%s" % traceback.format_exc())
        return 1
    finally:
        try:
            raw.close()
        except Exception as e:
            print("close_err=%r" % e)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pair")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(fn=do_pair)
    it = sub.add_parser("init-test")
    it.add_argument("--pdata", default=None)
    it.set_defaults(fn=do_init_test)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
