# pydrv/tools — Phase 1 bring-up tooling

Unlike `pydrv/diag/` (read-only), scripts here can **change sensor state**.

## capture_pgm.py — pair + capture-to-PGM

Validates the rev image pipeline on `06cb:00bc` headlessly (no matplotlib/X):
captures raw frames over TLS, reconstructs them via `libnative` (IPL), and
writes PGM files for inspection.

> **`--pair` is DESTRUCTIVE.** It takes ownership of the sensor (`PAIR/0x93`),
> re-keying it and **breaking any existing Windows fingerprint enrollment**.
> It is gated behind both `--pair` and `--yes`. Restoring Windows requires
> re-enrolling under Windows.

```sh
# 1c (destructive): take ownership + persist pairing data
sudo python tools/capture_pgm.py --pair --yes --pdata /etc/tudor/pdata.tpd --fprintd-setup

# 1d: capture N images -> PGM (needs pairing data from 1c)
sudo python tools/capture_pgm.py --capture 3 --pdata /etc/tudor/pdata.tpd --out /root/caps
```

Run from `pydrv/` as root. Without `--pair`/`--capture` it does nothing to the
sensor. If reconstruction produces garbage images, the 104-derived
`libnative` IPL likely diverges from Augusta's — extract `tudorIpl*` from
`synaWudfBioUsb103.dll` (Ghidra) and rebuild `sensor/libnative/`.
