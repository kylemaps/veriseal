"""Work out how much of a log a hacked robot could still change or remove.

For each export interval this runs a recording through the real export client and witness, then
sweeps the moment of the hack across the whole task and reports the worst case and the average:

    python bench/window.py --task 600 --epoch 1 --export 1,5,10,30,60 --out window.json

The windows are measured back from the moment of the hack:

    can alter, throw-away keys   change without any sign: back to the last signed head
    can alter, one key           change without any sign: back to the last head that left
    can delete                   remove, which shows as an interruption: back to the last head
                                 that left, with either kind of key

Heads that have not left at the moment of the hack don't count, since the hacker can stop them.
Before the start record leaves, the hacker can swap the whole key chain, so nothing counts yet.
Only the time up to the end of the task is swept.

A sealer that follows the recorder's file signs each head some time after its epoch ends, and
until then the epoch is still open to change. --head-delay adds that time to every window. Take
it from the ``head_delay`` in the ``stats.json`` that ``python -m veriseal.tail seal`` writes.

By default the clock is simulated, and each send takes the median round trip measured against a
real witness over HTTP: a local one, or the one at --url. With --live the recording runs in real
time, so run it against a witness on another machine to measure a real link. --outage START:LENGTH
scripts a lost link, in seconds from the start of the task.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import threading
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from veriseal.canonical import canonical_json
from veriseal.signing import generate_key, public_pem
from veriseal.stream import StreamSealer, begin_segment, start_hash
from veriseal.witness import (
    Delivery,
    EventLog,
    ExportClient,
    Send,
    Witness,
    http_sender,
    serve,
)

SECOND = 1_000_000_000
BLOCK = "00" * 32
TASK = "window"


class SimulatedClock:
    def __init__(self) -> None:
        self._now = 0

    def now(self) -> int:
        return self._now

    def wait_until(self, moment: int) -> None:
        self._now = max(self._now, moment)


class RealClock:
    def now(self) -> int:
        return time.monotonic_ns()

    def wait_until(self, moment: int) -> None:
        # Keep waiting until the clock itself reads *moment*. On a coarse clock (Windows, Python
        # 3.11 and older: about 16 ms) a sleep can end before the next tick, and a send would
        # then be timed just before a boundary it should fall after.
        while (left := moment - self.now()) > 0:
            time.sleep(left / SECOND)


def _sawtooth(start_ns: int, end_ns: int, resets: Iterable[tuple[int, int]]) -> tuple[int, float]:
    """Sweep the hack from start to end. Returns the worst window and the average.

    Each reset is (when, covered): from *when* on, everything up to *covered* is safe. Between
    resets the window grows at the speed of time, so its worst values come just before a reset.
    """
    covered, moment, worst, area = start_ns, start_ns, 0, 0.0
    for when, safe_to in sorted(resets):
        when = min(when, end_ns)
        worst = max(worst, when - covered)
        area += (when - moment) * ((moment - covered) + (when - covered)) / 2
        moment, covered = when, max(covered, safe_to)
    worst = max(worst, end_ns - covered)
    area += (end_ns - moment) * ((moment - covered) + (end_ns - covered)) / 2
    return worst, area / (end_ns - start_ns)


def windows(
    start_ns: int,
    end_ns: int,
    start_out_ns: int,
    closes: list[int],
    deliveries: list[Delivery],
    head_delay_ns: int = 0,
) -> dict[str, float]:
    """The attacker's windows in seconds, from what happened during one recording.

    *head_delay_ns* is how long after an epoch ends its head is signed. A head protects up to
    the end of its epoch, but only from the moment it is signed, and it can't leave before that.
    """
    signed = [(max(moment + head_delay_ns, start_out_ns), moment) for moment in closes]
    left = [(max(d.delivered_ns + head_delay_ns, start_out_ns), d.closed_ns) for d in deliveries]
    alter_worst, alter_mean = _sawtooth(start_ns, end_ns, signed)
    delete_worst, delete_mean = _sawtooth(start_ns, end_ns, left)
    return {
        "can_alter_throwaway_worst_s": alter_worst / SECOND,
        "can_alter_throwaway_mean_s": alter_mean / SECOND,
        "can_alter_one_key_worst_s": delete_worst / SECOND,
        "can_alter_one_key_mean_s": delete_mean / SECOND,
        "can_delete_worst_s": delete_worst / SECOND,
        "can_delete_mean_s": delete_mean / SECOND,
        "sign_locally_only_s": (end_ns - start_ns) / SECOND,
    }


def record(
    task_ns: int,
    epoch_ns: int,
    every: int,
    send: Send,
    witness_pem: str,
    clock: SimulatedClock | RealClock,
    outages: Iterable[tuple[int, int]] = (),
    latency_ns: int = 0,
    retry_ns: int = SECOND,
    start_delay_ns: int = 0,
    log: Callable[[dict], None] | None = None,
    head_delay_ns: int = 0,
) -> dict[str, float]:
    """Run one recording with real heads and return its windows and export cost.

    *start_delay_ns* is how long after recording began the start record got out, for a recorder
    that doesn't wait for it.
    """
    began = clock.now()
    lost = [(began + first, began + first + length) for first, length in outages]

    def link(path: str, body: dict) -> dict:
        sent = clock.now()
        if any(first <= sent < last for first, last in lost):
            raise OSError("scripted outage")
        reply = send(path, body)
        clock.wait_until(sent + latency_ns)
        return reply

    epochs = math.ceil(task_ns / epoch_ns)
    keys, start = begin_segment(TASK, TASK, epochs, epoch_ns, BLOCK, generate_key())
    client = ExportClient(link, witness_pem, start, keys.public_keys, every, clock.now, log)
    sealer = StreamSealer(TASK, epoch_ns, keys.sign, start_hash(start))
    sealer.add("/t", 0, b"x")
    closes: list[int] = []
    head_bytes = 0
    client.begin()
    retry_at = None if not client.pending else clock.now() + retry_ns

    def retry_until(moment: int | None) -> None:
        nonlocal retry_at
        while retry_at is not None and (moment is None or retry_at < moment):
            clock.wait_until(retry_at)
            retry_at = None if client.flush() else clock.now() + retry_ns

    for index in range(1, epochs + 1):
        close_at = began + index * epoch_ns
        retry_until(close_at)
        clock.wait_until(close_at)
        if index < epochs:
            (head,) = sealer.add("/t", index * epoch_ns, b"x")[1]
        else:
            (head,) = sealer.finish()
        closes.append(clock.now())
        head_bytes += len(canonical_json(head))
        client.add(head)
        if client.pending:
            retry_at = None if client.flush() else clock.now() + retry_ns
    end = clock.now()
    retry_until(None)
    start_out = max(client.start_out_ns, began + start_delay_ns)
    result = windows(began, end, start_out, closes, client.deliveries, head_delay_ns)
    hours = (end - began) / SECOND / 3600
    result["sends_per_hour"] = len(client.deliveries) / hours
    result["bytes_per_hour"] = len(client.deliveries) * head_bytes / epochs / hours
    return result


def measure_latency(send: Send, witness_rounds: int) -> list[float]:
    """Time real head submissions to a witness over HTTP, in seconds, sorted."""
    epoch_ns = SECOND
    keys, start = begin_segment(TASK, TASK, witness_rounds + 1, epoch_ns, BLOCK, generate_key())
    sealer = StreamSealer(TASK, epoch_ns, keys.sign, start_hash(start))
    sealer.add("/t", 0, b"x")
    public_keys = [key.hex() for key in keys.public_keys]
    send("/start", {"record": start, "public_keys": public_keys})
    times = []
    for index in range(1, witness_rounds + 1):
        (head,) = sealer.add("/t", index * epoch_ns, b"x")[1]
        began = time.perf_counter()
        send("/heads", head)
        times.append(time.perf_counter() - began)
    return sorted(times)


def _outage(text: str) -> tuple[int, int]:
    first, length = text.split(":")
    return int(float(first) * SECOND), int(float(length) * SECOND)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--task", type=float, default=600.0, help="task length, in seconds")
    parser.add_argument("--epoch", type=float, default=1.0, help="checkpoint interval, in seconds")
    parser.add_argument("--export", default="1,5,10,30,60,120,300", help="seconds between sends")
    parser.add_argument("--outage", type=_outage, action="append", default=[])
    parser.add_argument("--retry", type=float, default=1.0, help="seconds between retries")
    parser.add_argument("--start-delay", type=float, default=0.0, help="see record()")
    parser.add_argument(
        "--head-delay", type=float, default=0.0, help="seconds from an epoch's end to its head"
    )
    parser.add_argument("--rounds", type=int, default=200, help="round trips to time")
    parser.add_argument("--url", help="a running witness; a local one is used if omitted")
    parser.add_argument("--witness-pub", type=Path, help="that witness's public key (PEM)")
    parser.add_argument("--live", action="store_true", help="run in real time")
    parser.add_argument(
        "--deliveries", type=Path, help="append every send attempt to this file, one JSON line each"
    )
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    key = generate_key()
    pem = public_pem(key)
    if args.url:
        if args.live and not args.witness_pub:
            parser.error("--live with --url needs --witness-pub")
        url = args.url
        if args.witness_pub:
            pem = args.witness_pub.read_text()
    else:
        server = serve(Witness(key))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_address[1]}"
    send = http_sender(url)
    times = measure_latency(send, args.rounds)
    latency = statistics.median(times)
    p95 = times[int(len(times) * 0.95)]
    print(f"round trip to the witness: median {latency * 1000:.2f} ms, p95 {p95 * 1000:.2f} ms")

    epoch_ns = int(args.epoch * SECOND)
    rows = []
    for export in [float(value) for value in args.export.split(",")]:
        every = max(1, round(export / args.epoch))
        if args.live:
            clock, link, latency_ns = RealClock(), send, 0
        else:
            local = Witness(key)
            clock, latency_ns = SimulatedClock(), int(latency * SECOND)

            def link(path: str, body: dict, local: Witness = local) -> dict:
                if path == "/start":
                    keys = [bytes.fromhex(value) for value in body["public_keys"]]
                    return local.register(body["record"], keys)
                return local.submit(body)

        log = (
            EventLog(args.deliveries, export_s=every * args.epoch, live=args.live)
            if args.deliveries
            else None
        )
        row = record(
            int(args.task * SECOND),
            epoch_ns,
            every,
            link,
            public_pem(key) if not args.live else pem,
            clock,
            args.outage,
            latency_ns,
            int(args.retry * SECOND),
            int(args.start_delay * SECOND),
            log,
            int(args.head_delay * SECOND),
        )
        if log:
            log.close()
        rows.append({"export_s": every * args.epoch, **row})
        print(
            f"export every {every * args.epoch:g} s: "
            f"alter {row['can_alter_throwaway_worst_s']:.3f} s with throw-away keys, "
            f"{row['can_alter_one_key_worst_s']:.3f} s with one key; "
            f"delete {row['can_delete_worst_s']:.3f} s; "
            f"{row['bytes_per_hour'] / 1000:.1f} KB/h"
        )
    if args.out:
        settings = {k: v for k, v in vars(args).items() if k in ("task", "epoch", "retry", "live")}
        settings |= {"outages_ns": args.outage, "start_delay": args.start_delay}
        settings["head_delay"] = args.head_delay
        report = {"settings": settings, "latency_ms": {"median": latency * 1000, "p95": p95 * 1000}}
        args.out.write_text(json.dumps(report | {"rows": rows}, indent=1))


if __name__ == "__main__":
    main()
