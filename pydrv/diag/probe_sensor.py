"""Read-only sensor identification via the rev pydrv Sensor class.

Constructs tudor.sensor.Sensor, which performs GET_VERSION + IOTA reads +
sensor public-key load, then prints the parsed identity / config. This
exercises more of the protocol than probe_getversion.py while staying
READ-ONLY: it does NOT pair, init (TLS), provision, or capture.

Requires the rev pydrv package. This file lives under pydrv/diag/ and prepends
pydrv/ to sys.path so it runs regardless of the current working directory.

Usage (as root):
    sudo python pydrv/diag/probe_sensor.py [PID_hex]
    e.g. sudo python pydrv/diag/probe_sensor.py 0x00bc   (default PID is 0x00bc)
"""
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usb.core
from tudor.comm import USBCommunication
from tudor.sensor import Sensor

VID = 0x06CB
PID = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x00BC

dev = usb.core.find(idVendor=VID, idProduct=PID)
if dev is None:
    print("NO_DEVICE for %04x:%04x" % (VID, PID))
    sys.exit(2)
print("found %04x:%04x bus=%d addr=%d" % (VID, PID, dev.bus, dev.address))

comm = USBCommunication(dev)
try:
    s = Sensor(comm)
    print("OK Sensor constructed")
    print("fw=%d.%d.%d" % (s.fw_major, s.fw_minor, s.fw_build_num))
    print("product_id=%s" % s.product_id)
    print("advanced_security=%s" % s.advanced_security)
    print("key_flag=%s" % s.key_flag)
    print("provision_state=%s" % s.prov_state)
    print("bootloader_mode=%s" % s.in_bootloader_mode())
    print("cfg_ver=%d.%d.%d" % (s.cfg_ver.major, s.cfg_ver.minor, s.cfg_ver.revision))
    print("wbf_param=0x%x" % s.wbf_param_iota.param)
    print("sensor_id=%s" % s.id.hex())
    print("pub_key_loaded=%s" % (s.pub_key is not None))
except Exception:
    print("ERR:\n%s" % traceback.format_exc())
finally:
    try:
        comm.close()
    except Exception as e:
        print("close_err=%r" % e)
