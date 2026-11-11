"""An independent check of a streaming seal, written from SPEC-stream.md alone.

    python conformance/check_stream.py LOG.mcap SEAL_DIR [--max-lag-ms 100]

It imports nothing from veriseal: only the standard library, `cryptography` for Ed25519, and
`mcap` to read the log's messages. It prints OK, LATE or FAILED with a reason, and exits 0, 2
or 1. The tests run it on the vectors in conformance/stream/ and compare it with the
reference verifier, so the specification and the code cannot drift apart unnoticed.

It checks one segment against the start record and keys in SEAL_DIR, like the reference
command. A real check takes the start hash and identity key from where they were published.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from mcap.reader import make_reader

OK, FAILED, LATE = 0, 1, 2


def canonical(value: object) -> bytes:
    text = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return text.encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(topic: str, log_time_ns: int, payload: bytes) -> bytes:
    name = topic.encode("utf-8")
    preimage = (
        b"veriseal-leaf-v1\x00"
        + len(name).to_bytes(4, "big")
        + name
        + log_time_ns.to_bytes(8, "big")
        + payload
    )
    return sha256(b"\x00" + preimage)


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 section 2.1."""
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return sha256(b"\x01" + merkle_root(leaves[:split]) + merkle_root(leaves[split:]))


def signed_ok(public: Ed25519PublicKey, label: bytes, record: dict) -> bool:
    unsigned = {key: value for key, value in record.items() if key != "signature"}
    try:
        signature = base64.b64decode(record["signature"], validate=True)
        public.verify(signature, label + b"\x00" + canonical(unsigned))
    except (InvalidSignature, ValueError, KeyError):
        return False
    return True


def check_start(start: dict, identity_pem: str, public_keys: list[bytes]) -> str | None:
    identity = serialization.load_pem_public_key(identity_pem.encode("utf-8"))
    raw = identity.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    commitment = merkle_root([sha256(b"veriseal-epoch-commit-v0\x00" + key) for key in public_keys])
    if start.get("schema") != "veriseal-start-v0":
        return "unknown start record schema"
    if start.get("alg") != "Ed25519":
        return "unknown signature algorithm"
    if start.get("kid") != sha256(raw).hex():
        return "start record names a different identity key"
    if start.get("key_commitment") != commitment.hex():
        return "public keys do not match the start record"
    if not signed_ok(identity, b"veriseal-start-v0", start):
        return "bad start record signature"
    return None


def check_heads(heads: list[dict], start: dict, public_keys: list[bytes]) -> str | None:
    start_hash = sha256(canonical(start)).hex()
    previous, size = "00" * 32, 0
    for position, head in enumerate(heads):
        if head.get("schema") != "veriseal-head-v0" or head.get("epoch") != position:
            return f"head {position} is missing, out of order or of an unknown schema"
        if head["task_id"] != start["task_id"] or head["start"] != start_hash:
            return f"head {position} belongs to another task or start record"
        if head["prev_head"] != previous:
            return f"head {position} does not link to the one before"
        if (head["origin_ns"], head["epoch_ns"]) != (heads[0]["origin_ns"], start["epoch_ns"]):
            return f"head {position} disagrees on when epochs start"
        if head["tree_size"] < size or len(head["late"]) > head["tree_size"] - size:
            return f"head {position} has an impossible size"
        if position >= len(public_keys):
            return f"head {position} has no key"
        key = Ed25519PublicKey.from_public_bytes(public_keys[position])
        if not signed_ok(key, b"veriseal-head-v0", head):
            return f"head {position} has a bad signature"
        if head["final"] and position != len(heads) - 1:
            return "heads continue after the final head"
        previous, size = sha256(canonical(head)).hex(), head["tree_size"]
    if not heads or not heads[-1]["final"]:
        return "the final head is missing"
    return None


def check_log(messages: list, heads: list[dict], max_lag_ns: int) -> tuple[int, str]:
    origin, epoch_ns = heads[0]["origin_ns"], heads[0]["epoch_ns"]
    listed: dict[bytes, list[int]] = {}
    for head in heads:
        for value in head["late"]:
            listed.setdefault(bytes.fromhex(value), []).append(head["epoch"])
    epochs: list[list[tuple[int, bytes]]] = [[] for _ in heads]
    late = worst_ns = 0
    for topic, log_time_ns, payload in messages:
        leaf = leaf_hash(topic, log_time_ns, payload)
        if listed.get(leaf):
            epoch = listed[leaf].pop(0)
            begins = origin + epoch * epoch_ns
            if log_time_ns >= begins:
                return FAILED, "a head lists an on-time message as late"
            late, worst_ns = late + 1, max(worst_ns, begins - log_time_ns)
        else:
            epoch = (log_time_ns - origin) // epoch_ns
            if not 0 <= epoch < len(heads):
                return FAILED, "a message falls outside every epoch"
        epochs[epoch].append((log_time_ns, leaf))
    leaves: list[bytes] = []
    for head, members in zip(heads, epochs, strict=True):
        leaves += [leaf for _, leaf in sorted(members)]
        if len(leaves) != head["tree_size"] or merkle_root(leaves).hex() != head["root"]:
            return FAILED, f"the log does not match head {head['epoch']}"
    if worst_ns > max_lag_ns:
        return LATE, f"{late} messages sealed up to {worst_ns / 1e9:.3f} s after their times"
    return OK, f"{len(leaves)} messages match {len(heads)} heads; {late} late"


def check(log: Path, folder: Path, max_lag_ns: int = 100_000_000) -> tuple[int, str]:
    start = json.loads((folder / "start.json").read_bytes())
    keys = json.loads((folder / "keys.json").read_text(encoding="utf-8"))
    public_keys = [bytes.fromhex(key) for key in keys["public_keys"]]
    heads = [json.loads(line) for line in (folder / "heads.jsonl").read_bytes().splitlines()]
    with open(log, "rb") as file:
        messages = [
            (channel.topic, message.log_time, message.data)
            for _, channel, message in make_reader(file).iter_messages()
        ]
    try:
        problem = check_start(start, keys["identity"], public_keys)
        problem = problem or check_heads(heads, start, public_keys)
        if problem:
            return FAILED, problem
        return check_log(messages, heads, max_lag_ns)
    except (KeyError, TypeError, ValueError):
        return FAILED, "a record is malformed"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", type=Path)
    parser.add_argument("seal_dir", type=Path)
    parser.add_argument("--max-lag-ms", type=float, default=100.0)
    args = parser.parse_args(argv)
    verdict, reason = check(args.log, args.seal_dir, int(args.max_lag_ms * 1_000_000))
    print(f"{('OK', 'FAILED', 'LATE')[verdict]}: {reason}")
    return verdict


if __name__ == "__main__":
    sys.exit(main())
