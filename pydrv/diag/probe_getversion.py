"""Read-only GET_VERSION probe for Synaptics Tudor / Augusta sensors.

Self-contained: needs only pyusb (no tudor package required). Sends the
unencrypted GET_VERSION (0x01) command and decodes the firmware / product /
provision fields.

READ-ONLY: issues only GET_VERSION plus a USB reset on close. Does NOT pair,
provision, or otherwise change sensor state, so it is safe to run against a
sensor that is enrolled under another OS (e.g. Windows).

Usage (as root; the sensor's vendor interface must be free / no kernel driver):
    sudo python probe_getversion.py [PID_hex]
    e.g. sudo python probe_getversion.py 0x00bc   (default PID is 0x00bc)

Response layout (from rev/proto.txt + observed on 06cb:00bc fw 10.1):
    [0:2]   status (0x0000 == success)
    [6:10]  fw build number (u32 LE)
    [10]    fw major
    [11]    fw minor
    [13]    product id (ASCII; 'A' == provisioned app mode, 'B'/'C' bootloader)
    [18:24] sensor id
    [24]    flags1 (bit0 = advanced security present)
    [25]    flags2 (bit5 = key flag -> use the *-kf sensor key)
    [37]    provision state (& 0x0f; 3 == provisioned)
"""
import sys
import struct
import usb.core
import usb.util

VID = 0x06CB
PID = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x00BC

CMD_EP = 0x01
RESP_EP = 0x81
GET_VERSION = 0x01


def main():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print("NO_DEVICE for %04x:%04x" % (VID, PID))
        return 2
    print("found %04x:%04x bus=%d addr=%d" % (VID, PID, dev.bus, dev.address))

    dev.set_configuration()
    cfg = dev.get_active_configuration()
    intf = cfg[(0, 0)]
    for i in range(cfg.bNumInterfaces):
        if dev.is_kernel_driver_active(i):
            dev.detach_kernel_driver(i)
    usb.util.claim_interface(dev, intf.bInterfaceNumber)
    try:
        dev.write(CMD_EP, struct.pack("<B", GET_VERSION), 2000)
        resp = bytes(dev.read(RESP_EP, 256, 2000))
        print("resp_len=%d" % len(resp))
        print("raw=%s" % resp.hex())
        if len(resp) >= 38:
            status = struct.unpack("<H", resp[0:2])[0]
            build = struct.unpack("<I", resp[6:10])[0]
            major, minor = resp[10], resp[11]
            product_id = resp[13]
            flags1, flags2 = resp[24], resp[25]
            prov = resp[37] & 0x0F
            pc = chr(product_id) if 32 <= product_id < 127 else "?"
            print("status=0x%04x" % status)
            print("fw=%d.%d.%d" % (major, minor, build))
            print("product_id=0x%02x '%s'" % (product_id, pc))
            print("sensor_id=%s" % resp[18:24].hex())
            print("advanced_security=%s" % bool(flags1 & 0x01))
            print("key_flag=%s" % bool(flags2 & 0x20))
            print("provision_state=%d" % prov)
    finally:
        usb.util.release_interface(dev, intf.bInterfaceNumber)
        dev.reset()
    return 0


if __name__ == "__main__":
    sys.exit(main())
