"""Generate demo/sample.mcap — a synthetic AV-style log for the veriseal demo.

Topics: /pose, /imu, /vehicle/speed, /lidar/scan, /camera/front/info
Duration: 6 seconds at 10 Hz → ~200 messages total
Base time: 2025-06-16T00:00:00Z
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from mcap.writer import Writer

OUTPUT = Path(__file__).parent / "sample.mcap"

# 2025-06-16T00:00:00Z
# 2025-01-01T00:00:00Z = 1735689600s; +166 days = +14342400s → 1750032000s
BASE_NS = 1_750_032_000_000_000_000
STEP_NS = 100_000_000  # 100 ms → 10 Hz
N_STEPS = 60  # 6 seconds


def _pose(x: float, y: float, h: float) -> bytes:
    return json.dumps({"x": round(x, 4), "y": round(y, 4), "heading_deg": round(h, 2)}).encode()


def _imu(ax: float, ay: float, az: float, gz: float) -> bytes:
    return json.dumps(
        {"ax": round(ax, 4), "ay": round(ay, 4), "az": round(az, 4), "gz": round(gz, 4)}
    ).encode()


def _speed(mps: float) -> bytes:
    return json.dumps({"speed_mps": round(mps, 3)}).encode()


def _lidar(ranges: list[float]) -> bytes:
    return json.dumps({"ranges": [round(r, 2) for r in ranges]}).encode()


def _cam(w: int, h: int) -> bytes:
    return json.dumps({"width": w, "height": h, "encoding": "bgr8"}).encode()


messages: list[tuple[str, int, bytes]] = []

for i in range(N_STEPS):
    t = BASE_NS + i * STEP_NS
    angle_deg = i * 6  # 6° per step → full circle in 60 steps
    heading = angle_deg % 360
    r = 5.0
    x = r * math.cos(math.radians(angle_deg))
    y = r * math.sin(math.radians(angle_deg))
    spd = 2.0 + 0.4 * math.sin(math.radians(angle_deg * 2))

    messages.append(("/pose", t, _pose(x, y, heading)))
    messages.append(
        ("/imu", t, _imu(0.12 * math.sin(angle_deg), 0.04, 9.806, 0.015 * math.cos(angle_deg)))
    )
    messages.append(("/vehicle/speed", t, _speed(spd)))

    if i % 5 == 0:  # 2 Hz lidar
        ranges = [8.0 + 3.0 * math.sin(math.radians(j * 12 + angle_deg)) for j in range(16)]
        messages.append(("/lidar/scan", t, _lidar(ranges)))

    if i % 10 == 0:  # 1 Hz camera info
        messages.append(("/camera/front/info", t, _cam(1920, 1080)))

messages.sort(key=lambda m: (m[1], m[0]))

with open(OUTPUT, "wb") as f:
    writer = Writer(f)
    writer.start()
    schema_id = writer.register_schema(
        name="json_payload", encoding="json", data=b'{"type":"object"}'
    )
    channels: dict[str, int] = {}
    for topic in sorted({m[0] for m in messages}):
        channels[topic] = writer.register_channel(
            topic=topic, message_encoding="json", schema_id=schema_id
        )
    for topic, log_time, payload in messages:
        writer.add_message(
            channel_id=channels[topic],
            log_time=log_time,
            data=payload,
            publish_time=log_time,
        )
    writer.finish()

size_kb = OUTPUT.stat().st_size / 1024
print(f"Generated {OUTPUT}  ({len(messages)} messages, {size_kb:.1f} KB)")
print(f"Base time:  2025-06-16T00:00:00Z  ({BASE_NS} ns)")
print(f"End time:   2025-06-16T00:00:06Z  ({BASE_NS + N_STEPS * STEP_NS} ns)")
print()
print("Demo inspect window:")
print("  --from 2025-06-16T00:00:01Z  --to 2025-06-16T00:00:04Z  --topic /pose")
