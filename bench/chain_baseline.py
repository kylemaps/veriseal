"""Cost baseline: a keyed hash chain per topic, with a signed checkpoint per topic per interval.

    python bench/chain_baseline.py task.mcap --epoch-seconds 1 --out-dir out

This is the checkpoint structure of the closest earlier design for tamper-evident ROS logs
(White, Caiazza, Cortesi, Cho and Christensen, "Black Block Recorder", IEEE Robotics and
Automation Letters, 2019): every message extends an HMAC chain for its topic, and each topic's
newest link is signed and sent out once per interval. It is written from that description to
compare cost on the same log and computer, and shares no code with the original, which ran
inside the recorder and signed with ECDSA.

One long-lived key makes every link and signs every checkpoint. bench/measure.py runs this
with --chain-baseline and reports its time and energy beside the streaming seal's.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from collections.abc import Iterable
from pathlib import Path

from veriseal.canonical import canonical_json
from veriseal.formats import iter_messages
from veriseal.signing import generate_key, sign

SCHEMA = "chain-baseline-v0"


def chain_checkpoints(
    messages: Iterable[tuple[str, int, bytes]], epoch_ns: int, mac_key: bytes, signer
) -> list[dict]:
    """Chain every message onto its topic and sign each topic's link once per epoch."""
    links: dict[str, bytes] = {}
    counts: dict[str, int] = {}
    touched: set[str] = set()
    checkpoints: list[dict] = []
    origin: int | None = None
    epoch = 0

    def close() -> None:
        for topic in sorted(touched):
            checkpoint = {
                "schema": SCHEMA,
                "topic": topic,
                "epoch": epoch,
                "count": counts[topic],
                "link": links[topic].hex(),
            }
            signature = signer(canonical_json(checkpoint))
            checkpoint["signature"] = base64.b64encode(signature).decode("ascii")
            checkpoints.append(checkpoint)
        touched.clear()

    for topic, log_time_ns, payload in messages:
        if origin is None:
            origin = log_time_ns
        while (log_time_ns - origin) // epoch_ns > epoch:
            close()
            epoch += 1
        mac = hmac.new(mac_key, links.get(topic, b"\x00" * 32), hashlib.sha256)
        mac.update(log_time_ns.to_bytes(8, "big"))
        mac.update(payload)
        links[topic] = mac.digest()
        counts[topic] = counts.get(topic, 0) + 1
        touched.add(topic)
    close()
    return checkpoints


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", type=Path)
    parser.add_argument("--epoch-seconds", type=float, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    key = generate_key()
    checkpoints = chain_checkpoints(
        iter_messages(args.log),
        int(args.epoch_seconds * 1_000_000_000),
        os.urandom(32),
        lambda message: sign(key, message),
    )
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with open(args.out_dir / "checkpoints.jsonl", "wb") as out:
        for checkpoint in checkpoints:
            out.write(canonical_json(checkpoint) + b"\n")
    print(json.dumps({"checkpoints": len(checkpoints)}))


if __name__ == "__main__":
    main()
