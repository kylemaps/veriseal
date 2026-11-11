"""A witness: a small service off the robot that keeps its checkpoints and signs for them.

Prototype for a v2 format. The v1 seal and verify commands do not use this module.

Once a head has reached a witness, a hacked robot can no longer change or remove it, and each
head's hash chain fixes every head before it. So the export client only ever offers the newest
head: after an outage one send covers the whole gap, and the robot needs no growing queue.

The witness checks each head against the keys committed in the start record, so nobody else can
fill its store with junk. It keeps the first head it sees for an epoch. A second, different head
for that epoch is refused and kept as a conflict, because two signed versions of the same epoch
are evidence of tampering.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from veriseal.canonical import canonical_json
from veriseal.signing import generate_key, load_private_pem, public_pem, sign, verify
from veriseal.stream import (
    HEAD_SCHEMA,
    START_SCHEMA,
    Segment,
    StreamResult,
    _signed_bytes,
    epoch_checker,
    head_hash,
    key_commitment,
    start_hash,
)

RECEIPT_SCHEMA = "veriseal-receipt-v0"
_RECEIPT_DOMAIN = b"veriseal-receipt-v0\x00"
_MAX_BODY = 8_000_000

Send = Callable[[str, dict], dict]


class Rejected(Exception):
    """The witness refused what it was sent."""


def check_receipt(receipt: dict, expected_hash: str, witness_pem: str) -> bool:
    """Check that the witness signed for exactly this hash."""
    try:
        if receipt["schema"] != RECEIPT_SCHEMA or receipt["hash"] != expected_hash:
            return False
        unsigned = {k: v for k, v in receipt.items() if k != "signature"}
        signature = base64.b64decode(receipt["signature"], validate=True)
    except (KeyError, TypeError, ValueError):
        return False
    return verify(witness_pem, _RECEIPT_DOMAIN + canonical_json(unsigned), signature)


class Witness:
    """Stores start records and heads, and signs a receipt for each.

    With *path*, everything is appended to that file and synced to disk before a receipt goes
    out, and read back on the next start, so a receipt always means the witness holds the head.
    Receipts that arrive together share one sync instead of paying for one each.
    """

    def __init__(
        self,
        key: Ed25519PrivateKey,
        path: Path | None = None,
        clock: Callable[[], int] = time.time_ns,
    ) -> None:
        self._key = key
        self._clock = clock
        self._lock = threading.Lock()
        self._sync_lock = threading.Lock()
        self._keys: dict[str, list[bytes]] = {}
        self._heads: dict[str, dict[int, dict]] = {}
        self._receipts: dict[str, dict] = {}
        self._places: dict[str, int] = {}  # receipt hash: its line in the store
        self._written = self._synced = 0
        self._store: BinaryIO | None = None
        self.conflicts: list[dict] = []
        if path:
            if path.exists():
                for line in path.read_bytes().splitlines():
                    self._load(json.loads(line))
            self._store = open(path, "ab")

    def close(self) -> None:
        if self._store:
            self._store.close()
            self._store = None

    def _load(self, event: dict) -> None:
        if event["kind"] == "start":
            start = event["receipt"]["hash"]
            self._keys[start] = [bytes.fromhex(key) for key in event["public_keys"]]
            self._heads[start] = {}
            self._receipts[start] = event["receipt"]
        elif event["kind"] == "head":
            head = event["head"]
            self._heads[head["start"]][head["epoch"]] = head
            self._receipts[event["receipt"]["hash"]] = event["receipt"]
        else:
            self.conflicts.append(event["head"])

    def _keep(self, event: dict) -> int:
        """Hold *event* and write it to the store. Call with the lock held, then :meth:`_sync`.

        Returns the event's line in the store, 0 without one.
        """
        self._load(event)
        if not self._store:
            return 0
        self._store.write(canonical_json(event) + b"\n")
        self._store.flush()
        self._written += 1
        return self._written

    def _sync(self, place: int) -> None:
        """Return once the store is on disk up to line *place*.

        One sync covers every line written before it began, so callers that arrive while it
        runs usually find their line already safe.
        """
        if place <= self._synced:
            return
        with self._sync_lock:
            if place <= self._synced or not self._store:
                return
            with self._lock:
                target = self._written
            os.fsync(self._store.fileno())
            self._synced = target

    def _receipt(self, digest: str, epoch: int | None) -> dict:
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "hash": digest,
            "epoch": epoch,
            "received_ns": self._clock(),
        }
        signature = sign(self._key, _RECEIPT_DOMAIN + canonical_json(receipt))
        receipt["signature"] = base64.b64encode(signature).decode("ascii")
        return receipt

    def register(self, record: dict, public_keys: list[bytes]) -> dict:
        """Accept a start record and the public keys it commits to."""
        if record.get("schema") != START_SCHEMA:
            raise Rejected("unknown start record schema")
        if record.get("key_commitment") != key_commitment(public_keys):
            raise Rejected("public keys do not match the start record")
        digest = start_hash(record)
        with self._lock:
            if digest not in self._receipts:
                receipt = self._receipt(digest, None)
                keys = [key.hex() for key in public_keys]
                self._places[digest] = self._keep(
                    {"kind": "start", "record": record, "public_keys": keys, "receipt": receipt}
                )
            receipt, place = self._receipts[digest], self._places.get(digest, 0)
        self._sync(place)
        return receipt

    def _well_signed(self, head: dict, keys: list[bytes]) -> bool:
        epoch = head.get("epoch")
        if head.get("schema") != HEAD_SCHEMA or type(epoch) is not int:
            return False
        if not 0 <= epoch < len(keys):
            return False
        try:
            signature = base64.b64decode(head["signature"], validate=True)
            return epoch_checker(keys)(epoch, _signed_bytes(head), signature)
        except (KeyError, TypeError, ValueError, binascii.Error):
            return False

    def submit(self, head: dict) -> dict:
        """Accept a head that is newer than any held for its start record."""
        start = head.get("start")
        receipt: dict = {}
        conflict = False
        with self._lock:
            if start not in self._keys:
                raise Rejected("unknown start record")
            if not self._well_signed(head, self._keys[start]):
                raise Rejected("bad head")
            digest = head_hash(head)
            held = self._heads[start]
            if digest in self._receipts:
                receipt, place = self._receipts[digest], self._places.get(digest, 0)
            elif head["epoch"] in held:
                place, conflict = self._keep({"kind": "conflict", "head": head}), True
            else:
                newest = max(held, default=-1)
                if head["epoch"] < newest:
                    raise Rejected("a newer head is already held")
                if newest >= 0 and held[newest]["final"]:
                    raise Rejected("this recording already has a final head")
                receipt = self._receipt(digest, head["epoch"])
                place = self._keep({"kind": "head", "head": head, "receipt": receipt})
                self._places[digest] = place
        self._sync(place)
        if conflict:
            raise Rejected("a different head is held for this epoch")
        return receipt

    def heads(self, start: str) -> list[dict]:
        """Every head held for a start record, oldest first, once all of them are on disk."""
        with self._lock:
            held = self._heads.get(start, {})
            heads, place = [held[epoch] for epoch in sorted(held)], self._written
        self._sync(place)
        return heads


def check_witnessed(segments: list[Segment], witnessed: list[dict]) -> StreamResult:
    """Check a submission against what a witness holds: every held head must be in it, unchanged."""
    submitted = {
        (head["start"], head["epoch"]): head_hash(head)
        for segment in segments
        for head in segment.heads
    }
    for head in witnessed:
        if submitted.get((head["start"], head["epoch"])) != head_hash(head):
            return StreamResult(False, "a head the witness holds is missing", head["epoch"])
    return StreamResult(True, "submission contains every witnessed head")


def _handler(witness: Witness) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, body: object) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= _MAX_BODY:
                self._reply(413, {"error": "body is empty or too large"})
                return
            try:
                body = json.loads(self.rfile.read(length))
                if self.path == "/start":
                    keys = [bytes.fromhex(key) for key in body["public_keys"]]
                    self._reply(200, witness.register(body["record"], keys))
                elif self.path == "/heads":
                    self._reply(200, witness.submit(body))
                else:
                    self._reply(404, {"error": "no such path"})
            except Rejected as refused:
                self._reply(409, {"error": str(refused)})
            except (KeyError, TypeError, ValueError, AttributeError):
                self._reply(400, {"error": "malformed request"})

        def do_GET(self) -> None:
            if self.path.startswith("/heads/"):
                self._reply(200, witness.heads(self.path.removeprefix("/heads/")))
            else:
                self._reply(404, {"error": "no such path"})

        def log_message(self, format: str, *args: object) -> None:
            pass

    return Handler


def serve(witness: Witness, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """Make the HTTP server. The caller runs serve_forever, on a thread if it wants one."""
    return ThreadingHTTPServer((host, port), _handler(witness))


def http_sender(url: str, timeout: float = 5.0) -> Send:
    """Send JSON to a witness. A lost link raises OSError, and a refusal raises Rejected."""

    def send(path: str, body: dict) -> dict:
        request = urllib.request.Request(
            url.rstrip("/") + path,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as refused:
            if refused.code == 409:
                raise Rejected(json.loads(refused.read())["error"]) from refused
            raise

    return send


@dataclass(frozen=True)
class Delivery:
    """One head that reached the witness, timed on the robot's own clock.

    Both times come from one clock, so the numbers don't depend on the two machines agreeing.
    *delivered_ns* is when the receipt came back, a little after the head arrived, which errs
    towards a larger window.
    """

    epoch: int
    closed_ns: int
    delivered_ns: int


class EventLog:
    """Appends each event to a file as one JSON line, flushed at once so a crash loses little.

    *fields* go into every line, to tell runs apart when several share a file.
    """

    def __init__(self, path: Path, **fields: object) -> None:
        self._file = open(path, "a", encoding="utf-8")
        self._fields = fields

    def __call__(self, event: dict) -> None:
        self._file.write(json.dumps({**self._fields, **event}, sort_keys=True) + "\n")
        self._file.flush()

    def close(self) -> None:
        self._file.close()


class ExportClient:
    """Offers the newest head to a witness, and tries again until it gets a good receipt.

    *every* sets how often a head is offered, counted in epochs. The final head is always
    offered. Call :meth:`flush` when a head closes and on a retry timer while :attr:`pending`.

    *log*, if given, gets an event for every head that closes and every attempt to send,
    with how it went, so a run's outages can be worked out afterwards. Its times are on the
    robot's *clock*, except ``received_ns``, which is the witness's.
    """

    def __init__(
        self,
        send: Send,
        witness_pem: str,
        record: dict,
        public_keys: list[bytes],
        every: int = 1,
        clock: Callable[[], int] = time.monotonic_ns,
        log: Callable[[dict], None] | None = None,
    ) -> None:
        if every < 1:
            raise ValueError("every must be at least 1")
        self._send = send
        self._witness_pem = witness_pem
        self._record = record
        self._public_keys = public_keys
        self._every = every
        self._clock = clock
        self._log = log or (lambda event: None)
        self._offer: tuple[dict, int] | None = None
        self.start_out_ns: int | None = None
        self.deliveries: list[Delivery] = []

    @property
    def pending(self) -> bool:
        return self.start_out_ns is None or self._offer is not None

    def _attempt(self, path: str, body: dict, digest: str, event: dict) -> int | None:
        """Send once and log how it went. Returns when a good receipt came back, or None."""
        event = {**event, "sent_ns": self._clock()}
        try:
            receipt = self._send(path, body)
        except OSError as lost:
            self._log({**event, "outcome": "lost", "error": str(lost)[:200]})
            return None
        except Rejected as refused:
            self._log({**event, "outcome": "refused", "error": str(refused)})
            raise
        if not check_receipt(receipt, digest, self._witness_pem):
            self._log({**event, "outcome": "bad receipt"})
            return None
        delivered_ns = self._clock()
        received_ns = receipt["received_ns"]
        self._log(
            {
                **event,
                "outcome": "delivered",
                "delivered_ns": delivered_ns,
                "received_ns": received_ns,
            }
        )
        return delivered_ns

    def begin(self) -> bool:
        """Send the start record. Returns whether the witness has signed for it."""
        if self.start_out_ns is not None:
            return True
        body = {"record": self._record, "public_keys": [key.hex() for key in self._public_keys]}
        delivered_ns = self._attempt("/start", body, start_hash(self._record), {"event": "start"})
        if delivered_ns is None:
            return False
        self.start_out_ns = delivered_ns
        return True

    def add(self, head: dict) -> None:
        """Note a head that has just closed. It replaces any head still waiting to go."""
        offered = head["final"] or (head["epoch"] + 1) % self._every == 0
        closed_ns = self._clock()
        self._log(
            {"event": "closed", "epoch": head["epoch"], "closed_ns": closed_ns, "offered": offered}
        )
        if offered:
            self._offer = (head, closed_ns)

    def flush(self) -> bool:
        """Try to send what is waiting. Returns False if anything is still waiting."""
        if not self.begin():
            return False
        if self._offer is None:
            return True
        head, closed_ns = self._offer
        event = {"event": "head", "epoch": head["epoch"], "closed_ns": closed_ns}
        delivered_ns = self._attempt("/heads", head, head_hash(head), event)
        if delivered_ns is None:
            return False
        self.deliveries.append(Delivery(head["epoch"], closed_ns, delivered_ns))
        self._offer = None
        return True


def main(argv: list[str] | None = None, prog: str | None = None) -> None:
    """Run a witness until stopped. It has no login, so keep it on a private network."""
    parser = argparse.ArgumentParser(prog=prog, description=main.__doc__)
    parser.add_argument("--key", type=Path, help="witness signing key; omit for a new one")
    parser.add_argument("--store", type=Path, required=True, help="file that holds what it keeps")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args(argv)
    key = load_private_pem(args.key) if args.key else generate_key()
    print(public_pem(key), flush=True)
    server = serve(Witness(key, args.store), args.host, args.port)
    print(f"witness listening on {args.host}:{server.server_address[1]}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
