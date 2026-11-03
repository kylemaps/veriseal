# Sealing ROS 1 rosbags

veriseal can seal a ROS 1 `.bag` (rosbag1) directly, with no conversion step, using the
optional `rosbags` reader (pure Python, no ROS installation required):

```bash
pip install "veriseal[ros1]"
veriseal keygen --out signer.key.pem --pub signer.pub.pem   # once; reuse the key
veriseal seal drive.bag --key signer.key.pem --no-anchor --out drive.seal.json
veriseal verify drive.bag drive.seal.json --pubkey signer.pub.pem   # INTACT
```

The bag's messages are hashed as the same `(topic, log_time, payload)` leaves veriseal uses
for MCAP, so `seal`, `verify`, and `pack` all work identically; the manifest records
`"source": { "format": "rosbag1", ... }`. Tamper detection locates the changed message just
as it does for MCAP. (`veriseal inspect`, which exports a time window as a new MCAP, is
MCAP-only for now, so convert the bag first if you need it.)

You can still convert to MCAP first (below), for example to get a single MCAP file to open
in Foxglove, but sealing no longer requires it.

## Convert `.bag` to `.mcap` (optional)

Option A: [`rosbags`](https://gitlab.com/ternaris/rosbags) (pure Python, no ROS install needed).

```bash
pip install rosbags
rosbags-convert --src sample.bag --dst sample.mcap --dst-storage mcap
```

`rosbags-convert` with `--dst-storage mcap` writes a bag directory (`sample.mcap/metadata.yaml`
and `sample.mcap/sample.mcap.mcap`) instead of a single file, following the ROS 2 bag-directory
convention. Pull the inner `.mcap` file out if you want a flat file:

```bash
mv sample.mcap/sample.mcap.mcap ./sample_flat.mcap
rm -rf sample.mcap
mv sample_flat.mcap sample.mcap
```

Option B: the [`mcap` CLI](https://github.com/foxglove/mcap/tree/main/go/cli/mcap) (Go binary).

```bash
mcap convert sample.bag sample.mcap
```

## Seal and verify

```bash
veriseal seal sample.mcap --key signer.key.pem --no-anchor --out sample.seal.json
veriseal verify sample.mcap sample.seal.json --pubkey signer.pub.pem
# INTACT: signature valid, 10 messages, root 9a75174f...
```

Tamper detection works the same as on a native MCAP log. Flip a byte in a copy and re-verify:

```bash
veriseal verify sample.tampered.mcap sample.seal.json --pubkey signer.pub.pem
# TAMPERED
#   Source digest mismatch
#   Merkle root mismatch
#   MODIFIED  topic='/status' log_time=1700000000200000000
```

## Versions verified against

| Tool | Version |
|---|---|
| Python | 3.13.5 |
| `rosbags` | 0.11.3 |
| `mcap` (Python lib, used by veriseal) | 1.4.0 |
| veriseal | 0.1.x |

## Caveats

- Conversion is a separate, unsealed step. A seal of the MCAP proves the MCAP hasn't changed
  since sealing; it says nothing about whether the MCAP is a faithful conversion of the
  original `.bag`. If the conversion matters to your chain of custody, seal the original
  `.bag` as well (veriseal seals `.bag` files directly), so you can show the converted MCAP
  traces back to an untouched source file.
- `rosbags` needs `--src-typestore`/`--dst-typestore` flags if your bag uses non-standard or
  custom message definitions that aren't in its built-in `ros1_noetic` typestore.
