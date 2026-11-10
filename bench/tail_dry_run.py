"""Dry run of the tailing sealer, with no robot and no ROS.

    python bench/tail_dry_run.py task.bag --out tail-768k.json
    python bench/tail_dry_run.py task.bag --chunk-kib 0 --out tail-nochunk.json

This script plays the recorder. It writes a recorded task into a new MCAP file in real time,
each message when its time comes and stamped with that time, as ``ros2 bag record`` would.
Meanwhile ``python -m veriseal.tail seal`` runs as its own process and seals the file as it
grows. At the end the file is checked with the standard MCAP reader against what was sealed.

It reports how long after its time each message reached the sealer, how long after each epoch
ended its head was signed (time a hacker would still have to change it), any late messages,
and the sealer's CPU time. On the robot the same check runs with the real recorder (RUNS.md).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mcap.writer import CompressionType, Writer

from veriseal.formats import iter_messages
from veriseal.stream import Message, read_heads
from veriseal.tail import _percentiles, check_sealed

SECOND = 1_000_000_000
COMPRESSION = {
    "zstd": CompressionType.ZSTD,
    "lz4": CompressionType.LZ4,
    "none": CompressionType.NONE,
}


def replay(messages: list[Message], path: Path, args: argparse.Namespace) -> dict:
    """Write *messages* to *path* on their own schedule, stamped with the time they are due."""
    first = messages[0][1]
    began = time.time_ns() + SECOND // 2
    lags: list[int] = []
    options: dict = {"use_chunking": False}
    if args.chunk_kib:
        options = {
            "chunk_size": args.chunk_kib * 1024,
            "compression": COMPRESSION[args.compression],
        }
    with open(path, "wb") as file:
        writer = Writer(file, **options)
        writer.start()
        file.flush()
        schema = writer.register_schema(name="raw", encoding="", data=b"")
        channels: dict[str, int] = {}
        for topic, log_time, payload in messages:
            due = began + int((log_time - first) / args.speed)
            wait = (due - time.time_ns()) / SECOND
            if wait > 0:
                time.sleep(wait)
            if topic not in channels:
                channels[topic] = writer.register_channel(topic, "", schema)
            writer.add_message(channels[topic], log_time=due, data=payload, publish_time=due)
            if args.flush == "each":
                file.flush()
            lags.append(time.time_ns() - due)
        writer.finish()
    return _percentiles(lags)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("log", type=Path, help="a recorded task (.mcap or .bag)")
    parser.add_argument("--chunk-kib", type=int, default=768, help="0 writes no chunks")
    parser.add_argument("--compression", choices=sorted(COMPRESSION), default="zstd")
    parser.add_argument(
        "--flush",
        choices=("buffered", "each"),
        default="buffered",
        help="buffered: the file buffer empties when full, as C's stdio does; each: every message",
    )
    parser.add_argument("--speed", type=float, default=1.0, help="2 plays twice as fast")
    parser.add_argument("--epoch-seconds", type=float, default=1.0)
    parser.add_argument("--grace-seconds", type=float, default=6.0)
    parser.add_argument("--reorder-ms", type=float, default=100.0)
    parser.add_argument("--poll-ms", type=float, default=50.0)
    parser.add_argument("--work-dir", type=Path, help="keep the files here instead of deleting")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    messages = list(iter_messages(args.log))
    span_s = (messages[-1][1] - messages[0][1]) / SECOND / args.speed
    with tempfile.TemporaryDirectory() as scratch:
        work = args.work_dir or Path(scratch)
        work.mkdir(parents=True, exist_ok=True)
        log_path, sealed = work / "replay.mcap", work / "sealed"
        log_path.unlink(missing_ok=True)
        command = [
            sys.executable, "-m", "veriseal.tail", "seal", str(log_path),
            "--out-dir", str(sealed),
            "--epoch-seconds", str(args.epoch_seconds),
            "--grace-seconds", str(args.grace_seconds),
            "--reorder-ms", str(args.reorder_ms),
            "--poll-ms", str(args.poll_ms),
            "--max-seconds", str(span_s + 120),
            "--idle-seconds", "60",
        ]  # fmt: skip
        sealer = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
        assert sealer.stdout is not None
        sealer.stdout.readline()  # "ready", once its keys exist
        print(f"replaying {len(messages)} messages over {span_s:.0f} s ...", flush=True)
        writer_lag = replay(messages, log_path, args)
        sealer.communicate(timeout=180)
        stats = json.loads((sealed / "stats.json").read_text())
        result = check_sealed(log_path, sealed)
        heads = read_heads(sealed / "heads.jsonl")
        file_bytes = log_path.stat().st_size
    report = {
        "log": args.log.name,
        "chunk_kib": args.chunk_kib,
        "compression": args.compression if args.chunk_kib else None,
        "flush": args.flush,
        "speed": args.speed,
        "sealer": stats,
        "messages_in_log": len(messages),
        "messages_sealed": heads[-1]["tree_size"] if heads else 0,
        "heads": len(heads),
        "verified": result.ok,
        "verify_reason": result.reason,
        "late_messages": result.late_messages,
        "max_late_ms": result.max_late_ns / 1e6,
        "writer_lag": writer_lag,
        "file_bytes": file_bytes,
        "sealer_cpu_percent": round(100 * stats["cpu_s"] / stats["wall_s"], 2),
    }
    print(
        f"verified: {result.ok} ({result.reason}); sealed {report['messages_sealed']} of "
        f"{len(messages)} in {len(heads)} heads; late {result.late_messages}"
    )
    for name in ("read_delay", "head_delay"):
        delay = stats[name]
        print(
            f"{name.replace('_', ' ')} ms   p50 {delay['p50_ms']:.0f}  "
            f"p99 {delay['p99_ms']:.0f}  max {delay['max_ms']:.0f}"
        )
    print(
        f"sealer CPU {stats['cpu_s']:.2f} s over {stats['wall_s']:.0f} s "
        f"({report['sealer_cpu_percent']}% of one core); {stats['chunks']} chunks"
    )
    if args.out:
        args.out.write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
