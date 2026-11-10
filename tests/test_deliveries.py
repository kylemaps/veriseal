"""The delivery log behind the outage histogram, and the witness's shared disk syncs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

import pytest

from tests.test_bench_measure import REPO, _load
from tests.test_tail import _mcap_bytes, _messages
from tests.test_witness import Link, Recording
from veriseal import witness as witness_module
from veriseal.signing import generate_key, public_pem
from veriseal.stream import head_hash, start_hash
from veriseal.witness import EventLog, ExportClient, Rejected, Witness, check_receipt, serve

SECOND = 1_000_000_000


def _client(link, key, recording, events) -> ExportClient:
    ticks = iter(range(1, 1_000_000))
    return ExportClient(
        link,
        public_pem(key),
        recording.start,
        recording.public_keys,
        1,
        lambda: next(ticks),
        events.append,
    )


# The export client's log.


def test_the_log_has_every_close_and_every_attempt():
    key, recording, events = generate_key(), Recording(), []
    link = Link(Witness(key))
    client = _client(link, key, recording, events)
    assert client.begin()
    link.down = True
    client.add(recording.head())
    assert not client.flush()
    link.down = False
    client.add(recording.head())
    assert client.flush()
    assert [(e["event"], e.get("epoch"), e.get("outcome")) for e in events] == [
        ("start", None, "delivered"),
        ("closed", 0, None),
        ("head", 0, "lost"),
        ("closed", 1, None),
        ("head", 1, "delivered"),
    ]
    assert events[2]["error"] == "no link"
    delivered = events[-1]
    assert delivered["sent_ns"] < delivered["delivered_ns"] == client.deliveries[-1].delivered_ns
    assert type(delivered["received_ns"]) is int


def test_a_refusal_is_logged_then_raised():
    key, recording, events = generate_key(), Recording(), []
    client = _client(Link(Witness(key)), key, recording, events)
    client.begin()
    client.add({**recording.head(), "root": "00" * 32})
    with pytest.raises(Rejected):
        client.flush()
    assert (events[-1]["outcome"], events[-1]["error"]) == ("refused", "bad head")


def test_the_event_log_appends_one_json_line_per_event(tmp_path):
    path = tmp_path / "deliveries.jsonl"
    log = EventLog(path, export_s=10)
    log({"event": "closed", "epoch": 0})
    log({"event": "head", "outcome": "lost"})
    log.close()
    assert [json.loads(line) for line in path.read_text().splitlines()] == [
        {"event": "closed", "epoch": 0, "export_s": 10},
        {"event": "head", "outcome": "lost", "export_s": 10},
    ]


def test_the_window_script_can_log_its_deliveries():
    window = _load("window", REPO / "bench" / "window.py")
    key, events = generate_key(), []
    witness = Witness(key)

    def link(path: str, body: dict) -> dict:
        if path == "/start":
            keys = [bytes.fromhex(value) for value in body["public_keys"]]
            return witness.register(body["record"], keys)
        return witness.submit(body)

    clock = window.SimulatedClock()
    window.record(10 * SECOND, SECOND, 1, link, public_pem(key), clock, log=events.append)
    heads = [event for event in events if event["event"] == "head"]
    assert len(heads) == 10 and all(event["outcome"] == "delivered" for event in heads)


def test_the_tailing_sealer_writes_its_deliveries(tmp_path):
    key = generate_key()
    server = serve(Witness(key))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    public = tmp_path / "witness.pub.pem"
    public.write_text(public_pem(key))
    path, folder = tmp_path / "log.mcap", tmp_path / "sealed"
    path.write_bytes(_mcap_bytes(_messages(3, start_ns=time.time_ns() - 5 * SECOND)))
    command = [sys.executable, "-m", "veriseal.tail", "seal", str(path), "--out-dir", str(folder)]
    url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        done = subprocess.run(
            command
            + ["--max-seconds", "60", "--poll-ms", "5", "--witness", url]
            + ["--witness-pub", str(public)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    assert done.returncode == 0, done.stderr
    events = [json.loads(line) for line in (folder / "deliveries.jsonl").read_text().splitlines()]
    assert (events[0]["event"], events[0]["outcome"]) == ("start", "delivered")
    assert (events[-1]["event"], events[-1]["outcome"]) == ("head", "delivered")
    stats = json.loads((folder / "stats.json").read_text())
    assert stats["deliveries"][-1][0] == events[-1]["epoch"]


# The witness's disk syncs.


def test_one_sync_covers_every_line_written_before_it(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(witness_module.os, "fsync", calls.append)
    witness = Witness(generate_key(), tmp_path / "store.jsonl")
    with witness._lock:
        places = [witness._keep({"kind": "conflict", "head": {"n": n}}) for n in range(3)]
    witness._sync(places[0])
    witness._sync(places[2])
    assert len(calls) == 1
    witness.close()


def test_no_receipt_until_the_head_is_on_disk(tmp_path, monkeypatch):
    key, recording = generate_key(), Recording()
    store = tmp_path / "store.jsonl"
    witness = Witness(key, store)
    witness.register(recording.start, recording.public_keys)
    head = recording.head()

    def broken(fd: int) -> None:
        raise OSError("disk failed")

    monkeypatch.setattr(witness_module.os, "fsync", broken)
    with pytest.raises(OSError, match="disk failed"):
        witness.submit(head)
    monkeypatch.undo()
    assert check_receipt(witness.submit(head), head_hash(head), public_pem(key))
    witness.close()
    assert Witness(key, store).heads(head["start"]) == [head]


def test_heads_that_arrive_together_share_syncs(tmp_path, monkeypatch):
    calls = []
    real = os.fsync

    def slow(fd: int) -> None:
        calls.append(fd)
        time.sleep(0.005)
        real(fd)

    monkeypatch.setattr(witness_module.os, "fsync", slow)
    key, store = generate_key(), tmp_path / "store.jsonl"
    witness = Witness(key, store)
    recordings = [Recording() for _ in range(6)]
    for recording in recordings:
        witness.register(recording.start, recording.public_keys)
    before = len(calls)
    receipts = []

    def robot(recording: Recording) -> None:
        for _ in range(5):
            head = recording.head()
            receipts.append((head, witness.submit(head)))

    threads = [threading.Thread(target=robot, args=(recording,)) for recording in recordings]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(receipts) == 30
    assert all(check_receipt(r, head_hash(h), public_pem(key)) for h, r in receipts)
    assert len(calls) - before < 30
    witness.close()
    again = Witness(key, store)
    assert sum(len(again.heads(start_hash(r.start))) for r in recordings) == 30
