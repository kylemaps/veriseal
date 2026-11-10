"""The witness service and export client, including what a hacked robot can do to them."""

from __future__ import annotations

import copy
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from veriseal.signing import generate_key, public_pem
from veriseal.stream import (
    Segment,
    StreamSealer,
    begin_segment,
    head_hash,
    start_hash,
)
from veriseal.witness import (
    ExportClient,
    Rejected,
    Witness,
    check_receipt,
    check_witnessed,
    http_sender,
    serve,
)

SECOND = 1_000_000_000
TASK = "task-42"


class Recording:
    """A live recording that closes one epoch per call to :meth:`head`."""

    def __init__(self, keys: int = 12) -> None:
        self.keys, self.start = begin_segment(
            TASK, "0xrobot", keys, SECOND, "ab" * 32, generate_key()
        )
        self.public_keys = self.keys.public_keys
        self.sealer = StreamSealer(TASK, SECOND, self.keys.sign, start_hash(self.start))
        self.sealer.add("/t", 0, b"m0")
        self.closed = 0

    def head(self) -> dict:
        self.closed += 1
        return self.sealer.add("/t", self.closed * SECOND, b"m")[1][0]


@pytest.fixture
def key():
    return generate_key()


@pytest.fixture
def recording():
    return Recording()


@pytest.fixture
def witness(key, recording):
    held = Witness(key)
    held.register(recording.start, recording.public_keys)
    return held


def test_receipt_covers_exactly_the_head(key, witness, recording):
    head = recording.head()
    receipt = witness.submit(head)
    pem = public_pem(key)
    assert check_receipt(receipt, head_hash(head), pem)
    assert not check_receipt(receipt, "00" * 32, pem)
    assert not check_receipt(receipt, head_hash(head), public_pem(generate_key()))
    assert not check_receipt({**receipt, "received_ns": 1}, head_hash(head), pem)
    assert not check_receipt({}, head_hash(head), pem)


def test_start_record_must_match_its_keys(key, recording):
    with pytest.raises(Rejected, match="public keys"):
        Witness(key).register(recording.start, recording.public_keys[:-1])


def test_unknown_start_record_is_refused(key, recording):
    with pytest.raises(Rejected, match="unknown start record"):
        Witness(key).submit(recording.head())


def test_head_with_a_changed_root_is_refused(witness, recording):
    head = recording.head()
    with pytest.raises(Rejected, match="bad head"):
        witness.submit({**head, "root": "00" * 32})


@pytest.mark.parametrize("epoch", [-1, 500, "0", None, 1.0, True])
def test_head_with_a_bad_epoch_is_refused(witness, recording, epoch):
    with pytest.raises(Rejected, match="bad head"):
        witness.submit({**recording.head(), "epoch": epoch})


def test_head_with_a_garbled_signature_is_refused(witness, recording):
    with pytest.raises(Rejected, match="bad head"):
        witness.submit({**recording.head(), "signature": "not base64!"})


def test_sending_a_head_twice_is_harmless(witness, recording):
    head = recording.head()
    assert witness.submit(head) == witness.submit(head)
    assert witness.heads(head["start"]) == [head]


def test_a_second_version_of_an_epoch_is_refused_and_kept(witness, recording):
    """The hacker holds the key for the current epoch, but the witness already has that head."""
    hacker = copy.deepcopy(recording)
    honest = recording.head()
    witness.submit(honest)
    hacker.sealer.add("/t", SECOND // 2, b"forged")
    forged = hacker.head()
    assert forged["epoch"] == honest["epoch"]
    with pytest.raises(Rejected, match="different head"):
        witness.submit(forged)
    assert witness.conflicts == [forged]
    assert witness.heads(honest["start"]) == [honest]


def test_an_older_head_cannot_arrive_after_a_newer_one(witness, recording):
    old = recording.head()
    witness.submit(recording.head())
    with pytest.raises(Rejected, match="newer head"):
        witness.submit(old)


def test_nothing_is_accepted_after_the_final_head(witness, recording):
    hacker = copy.deepcopy(recording)
    witness.submit(recording.sealer.finish()[-1])
    hacker.head()
    with pytest.raises(Rejected, match="final head"):
        witness.submit(hacker.head())


def test_a_restarted_witness_keeps_what_it_held(key, recording, tmp_path: Path):
    store = tmp_path / "witness.jsonl"
    first = Witness(key, store)
    first.register(recording.start, recording.public_keys)
    head = recording.head()
    receipt = first.submit(head)
    second = Witness(key, store)
    assert second.heads(head["start"]) == [head]
    assert second.submit(head) == receipt
    assert second.submit(recording.head())["epoch"] == 1


def test_check_witnessed_needs_every_held_head(witness, recording):
    heads = [recording.head(), recording.head(), recording.head()]
    witness.submit(heads[1])
    held = witness.heads(heads[0]["start"])
    segment = Segment(recording.start, recording.public_keys, heads, [])
    assert check_witnessed([segment], held).ok
    segment.heads = heads[:1]
    result = check_witnessed([segment], held)
    assert (result.ok, result.epoch) == (False, 1)
    segment.heads = [heads[0], {**heads[1], "root": "00" * 32}, heads[2]]
    assert not check_witnessed([segment], held).ok


class Link:
    """A connection to an in-process witness that can be cut."""

    def __init__(self, witness: Witness) -> None:
        self.witness = witness
        self.down = False
        self.sent: list[str] = []

    def __call__(self, path: str, body: dict) -> dict:
        if self.down:
            raise OSError("no link")
        self.sent.append(path)
        if path == "/start":
            keys = [bytes.fromhex(value) for value in body["public_keys"]]
            return self.witness.register(body["record"], keys)
        return self.witness.submit(body)


def _client(link, key, recording, every: int = 1) -> ExportClient:
    ticks = iter(range(1, 1_000_000))
    return ExportClient(
        link, public_pem(key), recording.start, recording.public_keys, every, lambda: next(ticks)
    )


def test_client_needs_at_least_one_epoch(key, recording):
    with pytest.raises(ValueError):
        _client(Link(Witness(key)), key, recording, every=0)


def test_client_sends_the_start_record_first(key, recording):
    link = Link(Witness(key))
    client = _client(link, key, recording)
    client.add(recording.head())
    assert client.flush()
    assert link.sent == ["/start", "/heads"]
    assert not client.pending


def test_after_an_outage_one_send_covers_the_gap(key, recording):
    link = Link(Witness(key))
    client = _client(link, key, recording)
    client.begin()
    link.down = True
    heads = [recording.head() for _ in range(4)]
    for head in heads:
        client.add(head)
        assert not client.flush()
    assert client.pending
    link.down = False
    assert client.flush()
    assert [delivery.epoch for delivery in client.deliveries] == [3]
    assert link.witness.heads(heads[0]["start"]) == [heads[3]]


def test_client_offers_every_nth_head_and_always_the_final_one(key, recording):
    link = Link(Witness(key))
    client = _client(link, key, recording, every=3)
    for _ in range(4):
        client.add(recording.head())
        client.flush()
    client.add(recording.sealer.finish()[-1])
    client.flush()
    assert [delivery.epoch for delivery in client.deliveries] == [2, 4]


def test_a_receipt_from_the_wrong_witness_does_not_count(key, recording):
    link = Link(Witness(generate_key()))
    client = _client(link, key, recording)
    client.add(recording.head())
    assert not client.flush()
    assert client.deliveries == []
    assert client.pending


def test_delivery_times_come_from_the_robots_clock(key, recording):
    client = _client(Link(Witness(key)), key, recording)
    client.begin()
    client.add(recording.head())
    client.flush()
    (delivery,) = client.deliveries
    assert delivery.closed_ns < delivery.delivered_ns


@pytest.fixture
def server(witness):
    running = serve(witness)
    thread = threading.Thread(target=running.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{running.server_address[1]}"
    running.shutdown()
    running.server_close()
    thread.join()


def test_export_over_http(key, recording, server):
    client = _client(http_sender(server), key, recording)
    head = recording.head()
    client.add(head)
    assert client.flush()
    with urllib.request.urlopen(f"{server}/heads/{head['start']}") as reply:
        assert json.loads(reply.read()) == [head]


def test_a_refusal_over_http_is_not_a_lost_link(recording, server):
    with pytest.raises(Rejected, match="bad head"):
        http_sender(server)("/heads", {**recording.head(), "root": "00" * 32})


@pytest.mark.parametrize(
    ("path", "body", "status"),
    [("/heads", b"not json", 400), ("/heads", b"[1]", 400), ("/nowhere", b"{}", 404)],
)
def test_bad_requests_get_a_clear_status(server, path, body, status):
    request = urllib.request.Request(server + path, data=body)
    with pytest.raises(urllib.error.HTTPError) as refused:
        urllib.request.urlopen(request)
    assert refused.value.code == status


def test_a_dead_witness_looks_like_a_lost_link(key, recording):
    running = serve(Witness(key))
    url = f"http://127.0.0.1:{running.server_address[1]}"
    running.server_close()
    client = _client(http_sender(url, timeout=1), key, recording)
    assert not client.begin()
    assert client.pending
