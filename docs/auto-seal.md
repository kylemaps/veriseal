# Auto-sealing every recording

Add one step to your recording workflow and every log is sealed the moment it finishes.
The pattern is always the same: **record, then `veriseal seal` with a persistent signer key.**

## 1. Make a signer key once

Generate one Ed25519 key and reuse it for every recording, so all your seals share one signer
identity that others can pin:

```bash
mkdir -p ~/.veriseal
veriseal keygen --out ~/.veriseal/signer.key.pem --pub ~/.veriseal/signer.pub.pem
```

Keep `signer.key.pem` secret. Hand `signer.pub.pem` to anyone who needs to verify your logs
(see [Pinning](#4-pinning-the-signer), below). Losing the key does not compromise past seals,
but you cannot produce new seals under the same identity without it.

## 2. Post-record one-liner (bash)

Wrap `ros2 bag record` so the bag is sealed as soon as you stop it (Ctrl-C):

```bash
record_and_seal() {
  local name="$1"; shift
  ros2 bag record --storage mcap -o "$name" "$@"      # writes ./$name/${name}_0.mcap
  for f in "$name"/*.mcap; do
    veriseal seal "$f" --key ~/.veriseal/signer.key.pem --out "$f.seal.json"
  done
}

# usage:
record_and_seal drive /pose /status /tf
```

Every `*.mcap` the recorder produced now has a matching `*.mcap.seal.json` beside it.

## 3. ROS 2 launch integration

To seal automatically inside a launch file, run the seal step on the recorder's exit:

```python
# auto_seal.launch.py
from launch import LaunchDescription
from launch.actions import ExecuteProcess, RegisterEventHandler
from launch.event_handlers import OnProcessExit

SEAL = (
    'for f in drive/*.mcap; do '
    'veriseal seal "$f" --key ~/.veriseal/signer.key.pem --out "$f.seal.json"; '
    'done'
)

def generate_launch_description():
    record = ExecuteProcess(
        cmd=["ros2", "bag", "record", "--storage", "mcap", "-o", "drive", "/pose", "/status"],
        output="screen",
    )
    seal = ExecuteProcess(cmd=["bash", "-c", SEAL], output="screen")
    return LaunchDescription([
        record,
        RegisterEventHandler(OnProcessExit(target_action=record, on_exit=[seal])),
    ])
```

When recording stops, the seal runs against the finished file(s).

## 4. Pinning the signer

The seal proves a log matches a seal made by your key. For that to mean anything to a third
party, they must know the key is yours — so give them `signer.pub.pem` **out-of-band** (not
just inside the manifest) and have them pin it:

```bash
veriseal verify drive/drive_0.mcap drive/drive_0.mcap.seal.json --pubkey signer.pub.pem
```

Without `--pubkey`, a re-seal with a different key would still pass; pinning is what makes the
seal independently meaningful.

## Notes

- **Seal after recording completes.** These snippets seal the finished file, so the sealed
  bytes are the final recording, not a partial one.
- **Anchoring.** `veriseal seal` submits the Merkle root to OpenTimestamps by default (needs
  network). Add `--no-anchor` for offline/air-gapped rigs; run
  [`veriseal anchor upgrade`](../README.md#opentimestamps-anchor) later to pull in the Bitcoin
  confirmation once it lands.
- **ROS 1.** The same one-liner works on a `.bag` if you install `veriseal[ros1]` and seal the
  `.bag` directly — see [docs/ros1.md](ros1.md).
- **What it proves / doesn't.** Integrity-since-sealing and authenticity-to-your-key — not that
  the log's contents are true. See the [threat model](../README.md#threat-model).
