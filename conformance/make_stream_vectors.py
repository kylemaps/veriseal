"""Rebuild the streaming-seal vectors in conformance/stream/.

    python conformance/make_stream_vectors.py

Every key comes from a fixed seed and Ed25519 signatures are deterministic, so the seal files
come out byte for byte the same on every run. The keys are public test keys: never use them
for anything else.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcap.writer import Writer

from veriseal.canonical import canonical_json
from veriseal.signing import public_pem
from veriseal.stream import EpochKeys, StreamSealer, make_start_record, start_hash

HERE = Path(__file__).parent / "stream"
SECOND = 1_000_000_000
START_NS = 1_750_000_000 * SECOND
TASK = "conformance-task"
BLOCK = hashlib.sha256(b"veriseal conformance block").hexdigest()


def _seed(label: str) -> bytes:
    return hashlib.sha256(b"veriseal conformance " + label.encode()).digest()


def messages() -> list[tuple[str, int, bytes]]:
    """Four seconds on three topics, ten messages a second, with one pair sharing a time."""
    log = [
        (f"/topic{i % 3}", START_NS + i * SECOND // 10, f"message {i}".encode()) for i in range(40)
    ]
    log[21] = (log[21][0], log[20][1], log[21][2])
    return log


def write_mcap(path: Path, log: list[tuple[str, int, bytes]]) -> None:
    with open(path, "wb") as file:
        writer = Writer(file)
        writer.start(profile="", library="veriseal-conformance")
        schema = writer.register_schema(name="raw", encoding="", data=b"")
        channels: dict[str, int] = {}
        for topic, log_time, payload in log:
            if topic not in channels:
                channels[topic] = writer.register_channel(topic, "", schema)
            writer.add_message(channels[topic], log_time, payload, log_time)
        writer.finish()


def seal(folder: Path, arriving: list[tuple[str, int, bytes]], label: str) -> None:
    """Seal *arriving* in the order given, with no allowance for disorder."""
    folder.mkdir(parents=True, exist_ok=True)
    identity = Ed25519PrivateKey.from_private_bytes(_seed("identity"))
    keys = EpochKeys(8, seed=_seed(label))
    record = make_start_record(TASK, "conformance", keys.public_keys, SECOND, BLOCK, identity)
    heads: list[dict] = []
    leaves: list[bytes] = []
    sealer = StreamSealer(
        TASK,
        SECOND,
        keys.sign_only,
        start_hash(record),
        persist=heads.append,
        erase=keys.erase,
        on_leaves=leaves.extend,
    )
    for message in arriving:
        sealer.add(*message)
    sealer.finish()
    (folder / "start.json").write_bytes(canonical_json(record))
    keys_json = {
        "identity": public_pem(identity),
        "public_keys": [key.hex() for key in keys.public_keys],
    }
    (folder / "keys.json").write_text(json.dumps(keys_json, indent=1) + "\n", encoding="utf-8")
    (folder / "heads.jsonl").write_bytes(b"".join(canonical_json(head) + b"\n" for head in heads))
    (folder / "leaves.bin").write_bytes(b"".join(leaves))


def main(out: Path = HERE) -> None:
    out.mkdir(exist_ok=True)
    log = messages()
    write_mcap(out / "log.mcap", log)
    seal(out / "sealed", log, "ok")
    write_mcap(out / "log.reordered.mcap", log[20:] + log[:20])
    changed = list(log)
    changed[17] = (changed[17][0], changed[17][1], b"changed")
    write_mcap(out / "log.tampered.mcap", changed)
    write_mcap(out / "log.missing.mcap", log[:17] + log[18:])
    # One message is sealed 2.6 s after its time, another 100 ms after: exactly the default limit.
    slow, quick = log[4], log[19]
    arriving = [m for m in log if m not in (slow, quick)]
    arriving.insert(arriving.index(log[20]) + 1, quick)
    arriving.insert(arriving.index(log[30]) + 1, slow)
    write_mcap(out / "late.mcap", arriving)
    seal(out / "late-sealed", arriving, "late")


if __name__ == "__main__":
    main()
