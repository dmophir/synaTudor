"""Phase 1a read-only protocol shakedown for 06cb:00bc (Augusta).

Exercises additional *unencrypted* (pre-TLS) commands to confirm the Tudor
protocol framing matches on Augusta before any state-changing operation:
  - Sensor identity + IOTAs (via tudor.sensor.Sensor)
  - IPL IOTA dump (needed later for image reconstruction)
  - remote TLS session status (vendor control transfer 0x14)
  - GET_START_INFO (0x19)
  - STORAGE_INFO_GET (0x3e)  [tolerated if it needs TLS]

READ-ONLY: no pair / init(TLS) / provision / update / storage-format / capture.
Does not change sensor state; safe against a Windows-enrolled sensor.

Usage (root, from pydrv/): sudo python diag/shakedown_00bc.py [PID_hex]
"""
import os
import sys
import struct
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
from tudor.comm import USBCommunication, Command
from tudor.sensor import Sensor

VID = 0x06CB
PID = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x00BC


def hexpreview(b, n=64):
    return b[:n].hex() + ("..." if len(b) > n else "")


dev = usb.core.find(idVendor=VID, idProduct=PID)
if dev is None:
    print("NO_DEVICE for %04x:%04x" % (VID, PID))
    sys.exit(2)
print("found %04x:%04x bus=%d addr=%d" % (VID, PID, dev.bus, dev.address))

comm = USBCommunication(dev)
try:
    s = Sensor(comm)
    print("== identity ==")
    print("fw=%d.%d.%d product_id=%s prov=%s adv_sec=%s key_flag=%s"
          % (s.fw_major, s.fw_minor, s.fw_build_num, s.product_id,
             s.prov_state, s.advanced_security, s.key_flag))
    print("cfg_ver=%d.%d.%d wbf_param=0x%x sensor_id=%s"
          % (s.cfg_ver.major, s.cfg_ver.minor, s.cfg_ver.revision,
             s.wbf_param_iota.param, s.id.hex()))

    print("== IPL IOTA (0x1a) ==")
    ipl = s.ipl_iota.payload
    print("ipl_iota_len=%d ipl_iota[:64]=%s" % (len(ipl), hexpreview(ipl)))

    print("== remote TLS status (ctrl 0x14) ==")
    try:
        print("remote_tls_established=%s" % comm.remote_tls_status())
    except Exception as e:
        print("remote_tls_status_err=%r" % e)

    print("== GET_START_INFO (0x19) ==")
    try:
        sd = comm.send_command(struct.pack("<B", Command.GET_START_INFO), 0x44, raw=True)
        print("raw=%s" % sd.hex())
        if len(sd) >= 16:
            start_type, reset_type, start_status, sanity_panic, sanity_code = struct.unpack("<2xBBIII", sd[:16])
            print("status=0x%04x start_type=0x%02x reset_type=0x%02x start_status=0x%x sanity_panic=0x%x sanity_code=0x%x"
                  % (struct.unpack("<H", sd[:2])[0], start_type, reset_type, start_status, sanity_panic, sanity_code))
    except Exception as e:
        print("get_start_info_err=%r" % e)

    print("== STORAGE_INFO_GET (0x3e) [may require TLS] ==")
    try:
        si = comm.send_command(struct.pack("<B", Command.STORAGE_INFO_GET), 0x100, raw=True)
        print("status=0x%04x raw=%s" % (struct.unpack("<H", si[:2])[0], hexpreview(si, 96)))
    except Exception as e:
        print("storage_info_err=%r" % e)
except Exception:
    print("ERR:\n%s" % traceback.format_exc())
finally:
    try:
        comm.close()
    except Exception as e:
        print("close_err=%r" % e)
