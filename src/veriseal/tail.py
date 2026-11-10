"""Seal a log while the recorder is still writing it.

Prototype for a v2 format. The v1 seal and verify commands do not use this module.

The recorder (``ros2 bag record -s mcap``) writes the log as usual. This process reads the same
file as it grows and seals what it finds, so the seal covers exactly what is on disk, and the
robot's topics need no second subscriber. The price is time: a message can only be sealed once
the recorder has written it to the file, and a recorder that writes in big chunks makes the
sealer wait for each one. ``stats.json`` records how long, so the window this adds is measured.
With a witness, ``deliveries.jsonl`` records every attempt to send a head and how it went.

    python -m veriseal.tail seal task.mcap --out-dir sealed --epoch-seconds 1
    python -m veriseal.tail verify task.mcap --out-dir sealed

ROS 2 Humble's recorder writes MCAP in 768 KiB chunks by default, which on a one-minute
manipulation task reach the file about 2.6 s apart, so ``--grace-seconds`` must stay well above
that (6 s by default). ``ros2 bag record --storage-preset-profile fastwrite`` writes without
chunks, and then each head is signed within about 0.2 s of its epoch's end (measured in Docker).

``seal`` waits for the file to appear and stops when the recording ends. A recording that ends
properly gets a final head. One that stops any other way, because the recorder died or the
sealer was interrupted, keeps its last epochs open, and a verifier reports it as interrupted.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

from mcap.data_stream import ReadDataStream
from mcap.opcode import Opcode
from mcap.records import Channel, Chunk
from mcap.records import Message as McapMessage
from mcap.stream_reader import breakup_chunk

from veriseal.canonical import canonical_json
from veriseal.formats import iter_messages
from veriseal.signing import generate_key, load_private_pem, public_pem
from veriseal.stream import (
    Message,
    Segment,
    StreamResult,
    StreamSealer,
    begin_segment,
    read_heads,
    read_leaves,
    start_hash,
    verify_task,
)

MAGIC = b"\x89MCAP0\r\n"
SECOND = 1_000_000_000
_MAX_RECORD = 1 << 30  # a record longer than this means the file is damaged


class McapTail:
    """Reads the messages of an MCAP file while the recorder is still appending to it.

    Each :meth:`poll` returns the messages in records written completely since the last call,
    and leaves a record that is still being written for the next one. Messages inside a chunk
    appear only once the whole chunk is written. :attr:`done` turns true at the end of the data
    section, which the recorder writes when it stops.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.done = False
        self.bytes_read = 0
        self.chunks = 0
        self._file: BinaryIO | None = None
        self._buffer = bytearray()
        self._started = False
        self._topics: dict[int, str] = {}

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def poll(self) -> list[Message]:
        """Return the messages the recorder has finished writing since the last call."""
        if self.done:
            return []
        if self._file is None:
            try:
                self._file = open(self.path, "rb")
            except FileNotFoundError:
                return []
        data = self._file.read()
        self.bytes_read += len(data)
        self._buffer += data
        messages: list[Message] = []
        offset = 0
        if not self._started:
            if len(self._buffer) < len(MAGIC):
                return messages
            if self._buffer[: len(MAGIC)] != MAGIC:
                raise ValueError(f"{self.path.name} is not an MCAP file")
            offset, self._started = len(MAGIC), True
        while not self.done and len(self._buffer) - offset >= 9:
            opcode = self._buffer[offset]
            length = int.from_bytes(self._buffer[offset + 1 : offset + 9], "little")
            if length > _MAX_RECORD:
                raise ValueError(f"{self.path.name} has a record too long to be real")
            end = offset + 9 + length
            if end > len(self._buffer):
                break
            self._record(opcode, bytes(self._buffer[offset + 9 : end]), messages)
            offset = end
        del self._buffer[:offset]
        return messages

    def _record(self, opcode: int, content: bytes, messages: list[Message]) -> None:
        stream = ReadDataStream(BytesIO(content))
        if opcode == Opcode.CHUNK:
            self.chunks += 1
            records = breakup_chunk(Chunk.read(stream))
        elif opcode == Opcode.CHANNEL:
            records = [Channel.read(stream)]
        elif opcode == Opcode.MESSAGE:
            records = [McapMessage.read(stream, len(content))]
        else:
            if opcode in (Opcode.DATA_END, Opcode.FOOTER):
                self.done = True
            return
        for record in records:
            if isinstance(record, Channel):
                self._topics[record.id] = record.topic
            elif isinstance(record, McapMessage):
                topic = self._topics.get(record.channel_id)
                if topic is None:
                    raise ValueError("a message names a channel the file has not defined")
                messages.append((topic, record.log_time, bytes(record.data)))


def _percentiles(values_ns: list[int]) -> dict:
    if not values_ns:
        return {}
    ordered = sorted(values_ns)

    def pick(share: float) -> float:
        return ordered[min(len(ordered) - 1, int(share * len(ordered)))] / 1e6

    return {
        "p50_ms": pick(0.5),
        "p90_ms": pick(0.9),
        "p99_ms": pick(0.99),
        "max_ms": ordered[-1] / 1e6,
    }


@dataclass
class TailStats:
    """How far behind the recorder the sealer ran, and what it cost.

    *read_delays_ns* holds, per message, how long after its log time the sealer first read
    it. *head_delays_ns* holds, per head except the final one, how long after its epoch ended
    the head was signed. Until then a hacker who takes over can still change that epoch, so
    this delay adds to the time during which a log can be changed unnoticed.
    """

    messages: int = 0
    heads: int = 0
    late: int = 0
    finished: bool = False
    polls: int = 0
    bytes_read: int = 0
    chunks: int = 0
    cpu_s: float = 0.0
    wall_s: float = 0.0
    read_delays_ns: list[int] = field(default_factory=list)
    head_delays_ns: list[int] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "messages": self.messages,
            "heads": self.heads,
            "late": self.late,
            "finished": self.finished,
            "polls": self.polls,
            "bytes_read": self.bytes_read,
            "chunks": self.chunks,
            "cpu_s": round(self.cpu_s, 3),
            "wall_s": round(self.wall_s, 3),
            "read_delay": _percentiles(self.read_delays_ns),
            "head_delay": _percentiles(self.head_delays_ns),
        }


def seal_growing_log(
    tail: McapTail,
    sealer: StreamSealer,
    *,
    clock: Callable[[], int] = time.time_ns,
    sleep: Callable[[float], None] = time.sleep,
    poll_s: float = 0.05,
    idle_s: float | None = None,
    stop: Callable[[], bool] = lambda: False,
    on_head: Callable[[dict], None] = lambda head: None,
    on_poll: Callable[[], None] = lambda: None,
    max_skew_s: float = 600.0,
) -> TailStats:
    """Seal *tail*'s file as it grows, until the recording ends or the caller stops it.

    *clock* must be the clock the recorder stamps log times with (the system clock for
    ``ros2 bag record``), since the timer closes epochs by it. If the first message is more
    than *max_skew_s* away from that clock, the recorder is on another clock (simulation time,
    say), and sealing stops before the timer closes epochs that never happened.

    A recording that ends properly gets a final head. One that stops some other way, after
    *idle_s* without new data or when *stop* says so, keeps its last epochs open.
    """
    stats = TailStats()
    began_wall, began_cpu = time.perf_counter(), time.process_time()
    last_data = clock()

    def closed(heads: list[dict]) -> None:
        for head in heads:
            stats.heads += 1
            stats.late += len(head["late"])
            if not head["final"]:
                ends = head["origin_ns"] + (head["epoch"] + 1) * head["epoch_ns"]
                stats.head_delays_ns.append(clock() - ends)
            on_head(head)

    while True:
        messages = tail.poll()
        stats.polls += 1
        now = clock()
        if messages:
            last_data = now
            skew_s = (now - messages[0][1]) / SECOND
            if stats.messages == 0 and abs(skew_s) > max_skew_s:
                raise ValueError(
                    f"the first message is stamped {skew_s:.0f} s away from this computer's "
                    "clock; the recorder must use the same clock as the sealer"
                )
        for topic, log_time_ns, payload in messages:
            stats.read_delays_ns.append(now - log_time_ns)
            closed(sealer.add(topic, log_time_ns, payload)[1])
        stats.messages += len(messages)
        closed(sealer.tick(clock()))
        on_poll()
        if tail.done:
            closed(sealer.finish())
            stats.finished = True
            break
        if stop() or (idle_s is not None and clock() - last_data > idle_s * SECOND):
            break
        sleep(poll_s)
    stats.bytes_read, stats.chunks = tail.bytes_read, tail.chunks
    stats.cpu_s = time.process_time() - began_cpu
    stats.wall_s = time.perf_counter() - began_wall
    return stats


def _seal(args: argparse.Namespace) -> int:
    from veriseal.witness import EventLog, ExportClient, http_sender

    out: Path = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    epoch_ns = int(args.epoch_seconds * SECOND)
    key_count = int(args.max_seconds / args.epoch_seconds) + 2
    identity = load_private_pem(args.identity) if args.identity else generate_key()
    keys, record = begin_segment(
        args.task, args.executor, key_count, epoch_ns, args.block_hash, identity
    )
    (out / "start.json").write_bytes(canonical_json(record))
    (out / "keys.json").write_text(
        json.dumps(
            {"identity": public_pem(identity), "public_keys": [k.hex() for k in keys.public_keys]}
        )
    )
    client = log = None
    if args.witness:
        witness_pem = args.witness_pub.read_text()
        send = http_sender(args.witness, timeout=args.witness_timeout)
        log = EventLog(out / "deliveries.jsonl")
        client = ExportClient(
            send, witness_pem, record, keys.public_keys, args.export_every, log=log
        )
        client.begin()
    stopping = threading.Event()
    for name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: stopping.set())
    retry_at = 0.0

    def export(head: dict) -> None:
        if client:
            client.add(head)
            client.flush()

    def retry() -> None:
        nonlocal retry_at
        if client and client.pending and time.monotonic() >= retry_at:
            retry_at = time.monotonic() + args.retry_seconds
            client.flush()

    with open(out / "heads.jsonl", "wb") as heads_file, open(out / "leaves.bin", "wb") as leaves:

        def persist(head: dict) -> None:
            heads_file.write(canonical_json(head) + b"\n")
            heads_file.flush()
            os.fsync(heads_file.fileno())

        def write_leaves(batch: list[bytes]) -> None:
            leaves.write(b"".join(batch))
            leaves.flush()

        sealer = StreamSealer(
            args.task,
            epoch_ns,
            keys.sign_only,
            start_hash(record),
            persist=persist,
            erase=keys.erase,
            on_leaves=write_leaves,
            reorder_ns=int(args.reorder_ms * 1_000_000),
            grace_ns=int(args.grace_seconds * SECOND),
        )
        tail = McapTail(args.log)
        print(f"ready: sealing {args.log}", flush=True)
        try:
            stats = seal_growing_log(
                tail,
                sealer,
                poll_s=args.poll_ms / 1000,
                idle_s=args.idle_seconds,
                stop=stopping.is_set,
                on_head=export,
                on_poll=retry,
            )
        finally:
            tail.close()
            if log:
                log.close()
    summary = stats.summary()
    summary["config"] = {
        "epoch_s": args.epoch_seconds,
        "grace_s": args.grace_seconds,
        "reorder_ms": args.reorder_ms,
        "poll_ms": args.poll_ms,
    }
    if client:
        summary["deliveries"] = [
            [delivery.epoch, delivery.closed_ns, delivery.delivered_ns]
            for delivery in client.deliveries
        ]
    (out / "stats.json").write_text(json.dumps(summary, indent=1))
    ending = "final head written" if stats.finished else "stopped without a final head"
    print(f"sealed {stats.messages} messages in {stats.heads} heads; {ending}", flush=True)
    if stats.late:
        print(
            f"warning: {stats.late} messages reached the sealer after their epoch had closed. "
            "Record without chunks (--storage-preset-profile fastwrite) or raise "
            "--grace-seconds above the time between the recorder's chunks.",
            flush=True,
        )
    return 0


def check_sealed(log: Path, folder: Path) -> StreamResult:
    """Verify a log against a folder written by ``seal``.

    This trusts the identity key and start record in the folder. The real check takes both
    from the chain.
    """
    record = json.loads((folder / "start.json").read_bytes())
    keys = json.loads((folder / "keys.json").read_text())
    leaves_path = folder / "leaves.bin"
    leaves = read_leaves(leaves_path) if leaves_path.exists() else None
    try:
        messages = list(iter_messages(log))
    except Exception:  # noqa: BLE001 - a file cut short has no summary for the standard reader
        tail = McapTail(log)
        messages = tail.poll()
        tail.close()
    segment = Segment(
        record,
        [bytes.fromhex(key) for key in keys["public_keys"]],
        read_heads(folder / "heads.jsonl"),
        messages,
        leaves,
    )
    return verify_task(
        [segment], record["task_id"], record["block_hash"], keys["identity"], [start_hash(record)]
    )


def _verify(args: argparse.Namespace) -> int:
    result = check_sealed(args.log, args.out_dir)
    if result.ok:
        late = f"{result.late_messages} late, up to {result.max_late_ns / 1e6:.1f} ms"
        print(f"OK: {result.reason}; {late}")
    else:
        where = f"epoch {result.epoch}, message {result.message_index}"
        print(f"FAILED: {result.reason} ({where})")
    return 0 if result.ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser("seal", help="seal a log while it is being recorded")
    seal.add_argument("log", type=Path)
    seal.add_argument("--out-dir", type=Path, required=True)
    seal.add_argument("--epoch-seconds", type=float, default=1.0)
    seal.add_argument(
        "--grace-seconds",
        type=float,
        default=6.0,
        help="how long the timer waits past an epoch; must cover the recorder's chunk gap",
    )
    seal.add_argument(
        "--reorder-ms", type=float, default=100.0, help="disorder allowed between topics"
    )
    seal.add_argument("--poll-ms", type=float, default=50.0)
    seal.add_argument("--idle-seconds", type=float, help="give up after this long without data")
    seal.add_argument("--max-seconds", type=float, default=7200.0, help="longest task to expect")
    seal.add_argument("--task", default="dry-run")
    seal.add_argument("--executor", default="dry-run")
    seal.add_argument("--block-hash", default="00" * 32)
    seal.add_argument("--identity", type=Path, help="robot identity key; omit for a new one")
    seal.add_argument("--witness", help="witness URL; omit to keep heads on the robot")
    seal.add_argument("--witness-pub", type=Path)
    seal.add_argument("--witness-timeout", type=float, default=2.0)
    seal.add_argument("--export-every", type=int, default=1)
    seal.add_argument("--retry-seconds", type=float, default=1.0)
    check = commands.add_parser("verify", help="verify a finished log against its seal")
    check.add_argument("log", type=Path)
    check.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "seal" and args.witness and not args.witness_pub:
        parser.error("--witness needs --witness-pub")
    return _seal(args) if args.command == "seal" else _verify(args)


if __name__ == "__main__":
    sys.exit(main())
