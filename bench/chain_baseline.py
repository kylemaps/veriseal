"""Cost baseline: a hash chain per topic, with a signed checkpoint per topic per interval.

    python bench/chain_baseline.py task.mcap --epoch-seconds 1 --out-dir out

This is the checkpoint structure of the closest earlier design for tamper-evident ROS logs
(White, Caiazza, Cortesi, Cho and Christensen, "Black Block Recorder", IEEE Robotics and
Automation Letters, 2019). Each topic has a chain that starts from a digest derived from a
random nonce for the recording. Every message extends its topic's chain with an HMAC keyed by
the previous digest, over the message's time and data. A checkpoint is the pair (index,
digest), and a long-lived key signs the ones that are sent out.

This script is written from the paper's description to compare cost on the same log and
computer. It shares no code with the original, which ran as a rosbag2 storage plugin, signed
with ECDSA, and could send fewer checkpoints than it made. Here each topic's newest checkpoint
is signed once per interval. bench/measure.py runs this with --chain-baseline and reports its
time and energy beside the streaming seal's.
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
    messages: Iterable[tuple[str, int, bytes]], epoch_ns: int, nonce: bytes, signer
) -> list[dict]:
    """Chain every message onto its topic and sign each topic's newest link once per epoch.

    *nonce* is the recording's random starting digest. Each topic's chain starts from the
    digest before it, keyed over the topic's name, so the topics are tied to one recording.
    """
    links: dict[str, bytes] = {}
    genesis = nonce
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
                "index": counts[topic],
                "digest": links[topic].hex(),
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
        if topic not in links:
            genesis = hmac.new(genesis, topic.encode("utf-8"), hashlib.sha256).digest()
            links[topic] = genesis
        mac = hmac.new(links[topic], log_time_ns.to_bytes(8, "big"), hashlib.sha256)
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
