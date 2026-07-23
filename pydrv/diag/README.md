# pydrv/diag — read-only diagnostic probes

Small scripts used during Phase 0 to identify the `06cb:00bc` ("Augusta")
sensor and confirm it speaks the Tudor protocol. See
[`docs/00bc-porting.md`](../../docs/00bc-porting.md) for the full context.

**All probes here are READ-ONLY.** They issue only `GET_VERSION`, IOTA reads,
and a USB reset. They do **not** pair, init (TLS), provision, capture, or write
storage — so they will not disturb an enrollment made under another OS.

| Script | Deps | What it does |
|--------|------|--------------|
| `probe_getversion.py` | `pyusb` only | Sends `GET_VERSION`; prints raw bytes + decoded fw/product/provision. Self-contained. |
| `probe_sensor.py` | rev `pydrv` (`tudor`) | Builds `tudor.sensor.Sensor` (GET_VERSION + IOTA reads + sensor-key load); prints identity/config. |
| `shakedown_00bc.py` | rev `pydrv` (`tudor`) | Phase 1a: exercises more pre-TLS commands (GET_START_INFO, STORAGE_INFO_GET, remote TLS status, IPL IOTA dump) to confirm framing before any write. |
| `dryrun_pair_crypto.py` | rev `pydrv` + `cryptography` | Non-destructive: exercises the pairing/TLS crypto (HS key load, host-cert build/sign, cert + pairing-data serialization round-trips) with NO sensor I/O. Confirms the stateful path runs on this Python/cryptography before `pair`. |

Run as root (the sensor's vendor interface must be free; nothing binds
`06cb:00bc` in-kernel by default):

```sh
sudo python probe_getversion.py 0x00bc
sudo python pydrv/diag/probe_sensor.py 0x00bc
```

Known-good output for `06cb:00bc` fw 10.1 is recorded in the Phase 0 log of
`docs/00bc-porting.md`.
