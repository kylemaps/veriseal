# Sealing ROS 1 rosbags

veriseal can seal a ROS 1 `.bag` (rosbag1) **directly** — no conversion step — using the
optional `rosbags` reader (pure Python, no ROS installation required):

```bash
pip install "veriseal[ros1]"
veriseal seal drive.bag --no-anchor --out drive.seal.json
veriseal verify drive.bag drive.seal.json        # INTACT
```

The bag's messages are hashed as the same `(topic, log_time, payload)` leaves veriseal uses
for MCAP, so seal / verify / inspect / pack all work identically; the manifest records
`"source": { "format": "rosbag1", ... }`. Tamper detection locates the changed message just
as it does for MCAP.

Converting to MCAP first (below) is still fine — for example if you want a single MCAP
artifact to open in Foxglove — but it is no longer required to seal.

## Convert `.bag` → `.mcap` (optional)

**Option A — [`rosbags`](https://gitlab.com/ternaris/rosbags) (pure Python, no ROS install needed):**

```bash
pip install rosbags
rosbags-convert --src sample.bag --dst sample.mcap --dst-storage mcap
```

`rosbags-convert` with `--dst-storage mcap` writes a bag-directory (`sample.mcap/metadata.yaml`
+ `sample.mcap/sample.mcap.mcap`) rather than a single file — that's the ROS 2 bag-directory
convention, which `rosbags` reuses for its MCAP output. Pull the inner `.mcap` file out if you
want a flat file:

```bash
mv sample.mcap/sample.mcap.mcap ./sample_flat.mcap
rm -rf sample.mcap
mv sample_flat.mcap sample.mcap
```

**Option B — [`mcap` CLI](https://github.com/foxglove/mcap/tree/main/go/cli/mcap) (Go binary):**

```bash
mcap convert sample.bag sample.mcap
```

## Seal and verify

```bash
veriseal seal sample.mcap --no-anchor --out sample.seal.json
veriseal verify sample.mcap sample.seal.json
# INTACT — signature valid, 10 messages, root 9a75174f...
```

Tamper detection works the same as on a native MCAP log — flip a byte in a copy and re-verify:

```bash
veriseal verify sample.tampered.mcap sample.seal.json
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

- Conversion is a separate, unsealed step. veriseal proves the **MCAP** file hasn't been
  altered since sealing — it says nothing about whether the MCAP is a faithful conversion of
  the original `.bag`. If the conversion step itself matters to your chain of custody, seal
  the original `.bag` too (e.g. hash it and note the hash in your incident record) so you can
  show the converted MCAP traces back to an untouched source file.
- `rosbags` needs `--src-typestore`/`--dst-typestore` flags if your bag uses non-standard or
  custom message definitions that aren't in its built-in `ros1_noetic` typestore.
