"""Non-destructive dry-run of pydrv's pairing/TLS crypto path.

Exercises the exact crypto/serialization that `pair()` and `init()` use, WITHOUT
touching the sensor or any USB, to confirm it runs on this Python/cryptography
before the destructive pairing step:
  - load the bundled HS (host-signing) key
  - generate a host keypair + build & ECDSA-sign the host certificate
  - round-trip the 400-byte SensorCertificate (tobytes/frombytes)
  - self-verify the host-cert signature with the HS public key
  - round-trip SensorPairingData save/load

Touches NO sensor state. Safe to run anytime.

Usage (from pydrv/): python diag/dryrun_pair_crypto.py
"""
import os
import sys
import io
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cryptography
import cryptography.hazmat.primitives.asymmetric.ec as ecc
import cryptography.hazmat.primitives.hashes as hashes
from tudor.sensor import SensorCertificate, SensorPairingData
from tudor.sensor.pair import load_hs_key


def main():
    import platform
    print("python=%s cryptography=%s" % (platform.python_version(), cryptography.__version__))

    hs = load_hs_key()
    print("OK load_hs_key: curve=%s" % hs.curve.name)

    priv = ecc.generate_private_key(ecc.SECP256R1())
    cert = SensorCertificate.create_host_cert(priv.public_key())
    print("OK create_host_cert: cert_type=%d sig_len=%d" % (cert.cert_type, len(cert.signature)))

    blob = cert.tobytes()
    assert len(blob) == 400, "host cert not 400 bytes: %d" % len(blob)
    c2 = SensorCertificate.frombytes(blob)
    assert c2.pub_key.public_numbers() == priv.public_key().public_numbers(), "pubkey roundtrip mismatch"
    assert c2.cert_type == cert.cert_type
    print("OK SensorCertificate tobytes/frombytes round-trip (400 bytes)")

    hs.public_key().verify(cert.signature, cert.signbytes(), ecc.ECDSA(hashes.SHA256()))
    print("OK host-cert signature verifies against HS public key")

    pd = SensorPairingData(priv, cert, c2)
    buf = io.BytesIO()
    pd.save(buf)
    buf.seek(0)
    pd2 = SensorPairingData.load(buf)
    assert pd2.priv_key.private_numbers().private_value == priv.private_numbers().private_value
    assert len(buf.getvalue()) == 0x44 + 400 + 400
    print("OK SensorPairingData save/load round-trip (%d bytes)" % (0x44 + 400 + 400))

    print("ALL PAIR-CRYPTO DRY-RUN CHECKS PASSED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("DRY-RUN FAILED:\n%s" % traceback.format_exc())
        sys.exit(1)
