"""Attack a recording every way we know, and record what each design's verifier says.

    python bench/attacks.py --out attacks.json
    python bench/attacks.py --log task.bag

The hacker takes over the robot part-way through a task, with a full copy of the recorder at that
moment: its files, memory, surviving keys, identity key and wallet. For each attack they try every
strategy open to them, and the table shows the best result they can get:

    PASSES   the verifier accepts the log and shows nothing wrong
    FLAGGED  the verifier accepts the log but reports an interruption
    CAUGHT   the verifier rejects the log

Every cell comes from running the real verifier on the tampered log. EXPECTED holds the outcome each
cell should have, and a cell that differs is printed as a finding.

The default log is synthetic. The epoch, export interval, hack time and attack positions all scale
with the log's length, so a real log gives the same layout.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import io
import json
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from mcap.writer import Writer

from veriseal.formats import iter_messages
from veriseal.merkle import leaf_hash
from veriseal.seal import seal
from veriseal.signing import generate_key, public_pem, save_private_pem
from veriseal.stream import (
    Message,
    Segment,
    StreamResult,
    StreamSealer,
    begin_segment,
    key_signer,
    make_start_record,
    public_key_of,
    start_hash,
    verify_task,
)
from veriseal.verify import run_verification
from veriseal.witness import Witness, check_witnessed

SECOND = 1_000_000_000
TASK = "task-42"
OLD_TASK = "task-41"
ROBOT = "0xrobot"
BLOCK = "ab" * 32
OLD_BLOCK = "cd" * 32

EPOCHS = 30  # the log is cut into this many epochs
EXPORT_EVERY = 5  # a head leaves the robot every this many epochs
HACK_AT = 18.5  # epochs into the task
EXPORTED_AT = 7.5  # covered by a head that left before the hack
SIGNED_AT = 16.5  # covered by a signed head that had not left
UNSIGNED_AT = 18.2  # after the last signed head
HOUR = 3600 * SECOND

PASSES, FLAGGED, CAUGHT = "PASSES", "FLAGGED", "CAUGHT"
CONFIGS = (
    "v1 end seal",
    "throw-away keys",
    "one key + witness",
    "throw-away keys + witness",
    "throw-away keys + timed restarts",
    "one key, every head sent",
    "sealed key, every head sent",
)


@dataclass(frozen=True)
class Design:
    """One column of the table after the end seal.

    *erased*: throw-away keys. *exported*: heads go to a witness, one in every *export_every*.
    *timed*: start records are timed. *sealed*: the keys sit in hardware the hacker can't read,
    so the hacker can still feed the recorder but can't sign anything themselves.

    The last two columns model the earlier approach of one long-lived key with checkpoints sent
    to a ledger, without and with trusted hardware. They are its best case: every checkpoint is
    sent and the link never drops.
    """

    erased: bool
    exported: bool
    timed: bool = False
    export_every: int = EXPORT_EVERY
    sealed: bool = False


DESIGNS = (
    Design(erased=True, exported=False),
    Design(erased=False, exported=True),
    Design(erased=True, exported=True),
    Design(erased=True, exported=False, timed=True),
    Design(erased=False, exported=True, export_every=1),
    Design(erased=False, exported=True, export_every=1, sealed=True),
)


@dataclass
class Scenario:
    messages: list[Message]
    epoch_ns: int

    @classmethod
    def of(cls, messages: list[Message]) -> Scenario:
        span = messages[-1][1] - messages[0][1]
        return cls(messages, max(1, span // EPOCHS))

    def index_at(self, epochs: float) -> int:
        moment = self.messages[0][1] + int(epochs * self.epoch_ns)
        return next(i for i, message in enumerate(self.messages) if message[1] >= moment)

    @property
    def key_count(self) -> int:
        return EPOCHS + 3

    @property
    def not_before_ns(self) -> int:
        return self.messages[0][1]


@dataclass
class Run:
    """A recording up to the hack, and what the hacker holds at that moment."""

    scenario: Scenario
    hack_index: int
    identity: object
    start: dict
    public_keys: list[bytes]
    sealer: StreamSealer
    signer: Callable[[int, bytes], bytes]
    heads: list[dict]
    published: list[str]
    witnessed: list[dict] = field(default_factory=list)
    timed: bool = False
    sealed: bool = False


def _feed(sealer: StreamSealer, messages: list[Message]) -> list[dict]:
    heads = []
    for topic, log_time, payload in messages:
        heads += sealer.add(topic, log_time, payload)[1]
    return heads


def _new_chain(scenario: Scenario, identity, task: str, block: str, segment: int = 0):
    keys, record = begin_segment(
        task, ROBOT, scenario.key_count, scenario.epoch_ns, block, identity, segment
    )
    return keys, record, keys.public_keys, keys.sign


def _one_key_chain(scenario: Scenario, identity):
    key = generate_key()
    raw = key.public_key().public_bytes_raw()
    public_keys = [raw] * scenario.key_count
    record = make_start_record(TASK, ROBOT, public_keys, scenario.epoch_ns, BLOCK, identity)
    return None, record, public_keys, key_signer(key)


def record_until_hack(scenario: Scenario, design: Design, hack_index: int) -> Run:
    """Record honestly up to the hack, sending heads to a witness if this design has one.

    With *timed*, every start record is timed by the chain or a witness, and the recorder waits
    for that before recording. A restart the hacker publishes is timed at the hack.
    """
    identity = generate_key()
    if design.erased:
        _, start, public_keys, signer = _new_chain(scenario, identity, TASK, BLOCK)
    else:
        _, start, public_keys, signer = _one_key_chain(scenario, identity)
    sealer = StreamSealer(TASK, scenario.epoch_ns, signer, start_hash(start))
    heads = _feed(sealer, scenario.messages[:hack_index])
    witnessed = []
    if design.exported:
        witness = Witness(generate_key())
        witness.register(start, public_keys)
        for head in heads:
            if (head["epoch"] + 1) % design.export_every == 0:
                witness.submit(head)
        witnessed = witness.heads(start_hash(start))
    published = [start_hash(start)]
    return Run(
        scenario, hack_index, identity, start, public_keys, sealer, signer, heads, published,
        witnessed, design.timed, design.sealed,
    )  # fmt: skip


def _first_change(run: Run, target: list[Message]) -> int:
    honest = run.scenario.messages
    for index, (old, new) in enumerate(zip(honest, target, strict=False)):
        if old != new:
            return index
    return min(len(honest), len(target))


def keep_heads(run: Run, target: list[Message]) -> tuple[list[Segment], list[str]] | None:
    """Change the log and leave the signed heads alone."""
    sealer = copy.deepcopy(run.sealer)
    heads = run.heads + _feed(sealer, target[run.hack_index :]) + sealer.finish()
    # The honest sidecar, in tree order: by log time, ties broken by leaf hash.
    leaves = [leaf for _, leaf in sorted((m[1], leaf_hash(*m)) for m in run.scenario.messages)]
    return [Segment(run.start, run.public_keys, heads, target, leaves)], run.published


def resign(run: Run, target: list[Message]) -> tuple[list[Segment], list[str]] | None:
    """Keep the heads before the change and re-sign the rest with whatever keys survive."""
    first = _first_change(run, target)
    kept = run.heads[: sum(1 for head in run.heads if head["tree_size"] <= first)]
    signer = copy.deepcopy(run.signer)

    def sign_or_reuse(epoch: int, message: bytes) -> bytes:
        if epoch < len(kept):
            return base64.b64decode(kept[epoch]["signature"])
        return signer(epoch, message)

    sealer = StreamSealer(TASK, run.scenario.epoch_ns, sign_or_reuse, start_hash(run.start))
    try:
        heads = _feed(sealer, target) + sealer.finish()
    except ValueError:  # the key for that epoch no longer exists
        return None
    return [Segment(run.start, run.public_keys, heads, target)], run.published


def swap_chain(run: Run, target: list[Message]) -> tuple[list[Segment], list[str]] | None:
    """Start again with new keys and a new start record, keeping the published one in place."""
    _, record, public_keys, signer = _new_chain(run.scenario, run.identity, TASK, BLOCK)
    sealer = StreamSealer(TASK, run.scenario.epoch_ns, signer, start_hash(record))
    heads = _feed(sealer, target) + sealer.finish()
    return [Segment(record, public_keys, heads, target)], run.published


def fake_power_cut(run: Run, target: list[Message]) -> tuple[list[Segment], list[str]] | None:
    """Claim the power failed just before the change, and restart on a new key chain."""
    first = _first_change(run, target)
    kept = [head for head in run.heads if head["tree_size"] <= first]
    before = Segment(run.start, run.public_keys, kept, target[:first])
    _, record, public_keys, signer = _new_chain(run.scenario, run.identity, TASK, BLOCK, segment=1)
    sealer = StreamSealer(TASK, run.scenario.epoch_ns, signer, start_hash(record))
    heads = _feed(sealer, target[first:]) + sealer.finish()
    after = Segment(record, public_keys, heads, target[first:])
    return [before, after], run.published + [start_hash(record)]


def restamp_after_cut(run: Run, target: list[Message]) -> tuple[list[Segment], list[str]] | None:
    """Fake a power cut before the change, and move everything after it to just after the hack.

    The hacker owns the clock, so timestamps are theirs to choose. This beats any rule about
    when a restart may begin, at the price of a long, visible gap.
    """
    first = _first_change(run, target)
    if first >= len(target):
        return None
    hacked_at = run.scenario.messages[run.hack_index][1]
    shift = max(0, hacked_at + run.scenario.epoch_ns - target[first][1])
    moved = target[:first] + [(topic, t + shift, data) for topic, t, data in target[first:]]
    return fake_power_cut(run, moved)


STRATEGIES = (keep_heads, resign, swap_chain, fake_power_cut, restamp_after_cut)


def _publication_times(run: Run, published: list[str]) -> list[int]:
    """The honest start record left as recording began. Any later one left after the hack."""
    hacked_at = run.scenario.messages[run.hack_index][1]
    return [run.scenario.not_before_ns] + [hacked_at] * (len(published) - 1)


def judge(run: Run, segments: list[Segment], published: list[str]) -> tuple[str, StreamResult]:
    result = verify_task(
        segments,
        TASK,
        BLOCK,
        public_key_of(run.identity),
        published,
        not_before_ns=run.scenario.not_before_ns,
        published_at_ns=_publication_times(run, published) if run.timed else None,
    )
    if result.ok:
        witness = check_witnessed(segments, run.witnessed)
        if not witness.ok:
            return CAUGHT, witness
    if not result.ok:
        return CAUGHT, result
    return (FLAGGED if result.interrupted else PASSES), result


def best_outcome(run: Run, target: list[Message], restamp: bool = True) -> dict:
    """Try every strategy and keep the one that serves the hacker best.

    Among flagged results the hacker prefers the shortest gap, since a long one looks
    suspicious. *restamp* is off for attacks whose whole point is the timestamps.
    """
    rank = {CAUGHT: 0, FLAGGED: 1, PASSES: 2}
    best: dict | None = None
    best_key: tuple[int, float] | None = None
    for strategy in STRATEGIES:
        if strategy is restamp_after_cut and not restamp:
            continue
        if run.sealed and strategy is not keep_heads:
            continue  # every other strategy signs with a key the hacker can't reach
        attempt = strategy(run, target)
        if attempt is None:
            continue
        outcome, result = judge(run, *attempt)
        seam_s = max(result.seams_ns) / SECOND if result.seams_ns else None
        key = (rank[outcome], -(seam_s or 0.0))
        if best_key is None or key > best_key:
            best_key = key
            best = {
                "outcome": outcome,
                "strategy": strategy.__name__,
                "reason": result.reason,
                "epoch": result.epoch,
                "message": result.message_index,
                "seam_s": seam_s,
            }
    assert best is not None
    return best


def _altered(messages: list[Message], index: int) -> list[Message]:
    topic, log_time, _ = messages[index]
    return messages[:index] + [(topic, log_time, b"forged")] + messages[index + 1 :]


def _deleted(messages: list[Message], index: int) -> list[Message]:
    return messages[:index] + messages[index + 1 :]


def _reordered(messages: list[Message], index: int) -> list[Message]:
    """Make two messages happen the other way round, by swapping their times.

    Swapping them in the file alone changes nothing: readers and the verifier sort by time.
    """
    (topic_a, time_a, data_a), (topic_b, time_b, data_b) = messages[index : index + 2]
    swapped = [(topic_b, time_a, data_b), (topic_a, time_b, data_a)]
    return messages[:index] + swapped + messages[index + 2 :]


def _after_hack(scenario: Scenario) -> list[Message]:
    hack = scenario.index_at(HACK_AT)
    return scenario.messages[:hack] + [
        (topic, log_time, b"fabricated") for topic, log_time, _ in scenario.messages[hack:]
    ]


def _backdated_insert(scenario: Scenario) -> list[Message]:
    """After the hack, add a message stamped back inside an early, already sealed epoch."""
    hack = scenario.index_at(HACK_AT)
    topic, log_time, _ = scenario.messages[scenario.index_at(EXPORTED_AT)]
    fake = (topic, log_time + 1, b"fake bin success")
    return scenario.messages[:hack] + [fake] + scenario.messages[hack:]


def _fabricated(scenario: Scenario) -> list[Message]:
    return [(topic, log_time, b"fabricated") for topic, log_time, _ in scenario.messages]


def _backdated(scenario: Scenario) -> list[Message]:
    return [(topic, log_time - HOUR, payload) for topic, log_time, payload in scenario.messages]


# Name, then how to build the log the hacker wants, from the scenario.
TARGETS: dict[str, Callable[[Scenario], list[Message]]] = {
    "no attack": lambda s: s.messages,
    "alter a message that left": lambda s: _altered(s.messages, s.index_at(EXPORTED_AT)),
    "alter a signed message that had not left": lambda s: _altered(
        s.messages, s.index_at(SIGNED_AT)
    ),
    "alter a message after the last head": lambda s: _altered(s.messages, s.index_at(UNSIGNED_AT)),
    "delete a message that left": lambda s: _deleted(s.messages, s.index_at(EXPORTED_AT)),
    "swap the times of two messages that left": lambda s: _reordered(
        s.messages, s.index_at(EXPORTED_AT)
    ),
    "cut the end, back past the last head": lambda s: s.messages[: s.index_at(SIGNED_AT)],
    "fabricate everything after the hack": _after_hack,
    "re-seal the whole task from scratch": _fabricated,
    "backdate the log to before assignment": _backdated,
    "insert a backdated message after the hack": _backdated_insert,
}
# Attacks about timestamps, where moving the timestamps would defeat the attack's purpose.
TIME_ROWS = {"backdate the log to before assignment", "insert a backdated message after the hack"}
OLD_PROOF = "submit an old proof for this task"
BEFORE_START = "hacked before the start record left"

EXPECTED: dict[str, tuple[str, ...]] = {
    "no attack": (PASSES, PASSES, PASSES, PASSES, PASSES, PASSES, PASSES),
    "alter a message that left": (PASSES, FLAGGED, CAUGHT, CAUGHT, FLAGGED, CAUGHT, CAUGHT),
    "alter a signed message that had not left": (
        PASSES,
        FLAGGED,
        PASSES,
        FLAGGED,
        FLAGGED,
        CAUGHT,
        CAUGHT,
    ),
    "alter a message after the last head": (PASSES, PASSES, PASSES, PASSES, PASSES, PASSES, CAUGHT),
    "delete a message that left": (PASSES, FLAGGED, CAUGHT, CAUGHT, FLAGGED, CAUGHT, CAUGHT),
    "swap the times of two messages that left": (
        PASSES,
        FLAGGED,
        CAUGHT,
        CAUGHT,
        FLAGGED,
        CAUGHT,
        CAUGHT,
    ),
    "cut the end, back past the last head": (
        PASSES,
        FLAGGED,
        PASSES,
        FLAGGED,
        FLAGGED,
        CAUGHT,
        CAUGHT,
    ),
    "fabricate everything after the hack": (PASSES, PASSES, PASSES, PASSES, PASSES, PASSES, PASSES),
    "re-seal the whole task from scratch": (
        PASSES,
        FLAGGED,
        CAUGHT,
        CAUGHT,
        FLAGGED,
        CAUGHT,
        CAUGHT,
    ),
    "backdate the log to before assignment": (
        PASSES,
        CAUGHT,
        CAUGHT,
        CAUGHT,
        CAUGHT,
        CAUGHT,
        CAUGHT,
    ),
    "insert a backdated message after the hack": (
        PASSES,
        CAUGHT,
        CAUGHT,
        CAUGHT,
        CAUGHT,
        CAUGHT,
        CAUGHT,
    ),
    OLD_PROOF: (PASSES, CAUGHT, CAUGHT, CAUGHT, CAUGHT, CAUGHT, CAUGHT),
    BEFORE_START: (PASSES, PASSES, PASSES, PASSES, PASSES, PASSES, PASSES),
}


def _write_mcap(path: Path, messages: list[Message]) -> None:
    with open(path, "wb") as file:
        writer = Writer(file)
        writer.start()
        schema = writer.register_schema(name="raw", encoding="", data=b"")
        channels: dict[str, int] = {}
        for topic, log_time, payload in messages:
            if topic not in channels:
                channels[topic] = writer.register_channel(
                    topic=topic, message_encoding="", schema_id=schema
                )
            writer.add_message(
                channels[topic], log_time=log_time, data=payload, publish_time=log_time
            )
        writer.finish()


def v1_outcome(messages: list[Message], folder: Path) -> dict:
    """The end seal runs on the hacked robot, so it signs the hacked log with the real key."""
    log, key, public = folder / "log.mcap", folder / "key.pem", folder / "key.pub.pem"
    key.unlink(missing_ok=True)
    signing_key = generate_key()
    save_private_pem(signing_key, key)
    public.write_text(public_pem(signing_key))
    _write_mcap(log, messages)
    seal_path = folder / "log.seal.json"
    with contextlib.redirect_stdout(io.StringIO()):
        seal(log, key_path=key, out_path=seal_path, do_anchor=False)
    result = run_verification(log, json.loads(seal_path.read_bytes()), public)
    outcome = PASSES if result.ok else CAUGHT
    return {"outcome": outcome, "strategy": "seal the hacked log", "reason": "real v1 verify"}


def _old_proof_outcome(scenario: Scenario, design: Design) -> dict:
    """Finish a genuine older task, then offer its proof for this one."""
    run = record_until_hack(scenario, design, scenario.index_at(HACK_AT))
    identity = run.identity
    _, old_start, old_keys, old_signer = _new_chain(scenario, identity, OLD_TASK, OLD_BLOCK)
    sealer = StreamSealer(OLD_TASK, scenario.epoch_ns, old_signer, start_hash(old_start))
    heads = _feed(sealer, scenario.messages) + sealer.finish()
    old = Segment(old_start, old_keys, heads, scenario.messages)
    outcome, result = judge(run, [old], [start_hash(old_start)])
    return {"outcome": outcome, "strategy": "submit it as it is", "reason": result.reason}


def _before_start_outcome(scenario: Scenario, design: Design) -> dict:
    """The hacker owns the recorder from the first moment, so everything it reports is theirs."""
    run = record_until_hack(scenario, replace(design, exported=False), 0)
    fake = _fabricated(scenario)
    heads = _feed(run.sealer, fake) + run.sealer.finish()
    segments = [Segment(run.start, run.public_keys, heads, fake)]
    if design.exported:
        witness = Witness(generate_key())
        witness.register(run.start, run.public_keys)
        witness.submit(heads[-1])
        run.witnessed = witness.heads(start_hash(run.start))
    outcome, result = judge(run, segments, run.published)
    return {"outcome": outcome, "strategy": "record fabricated data", "reason": result.reason}


def run_matrix(scenario: Scenario) -> dict[str, list[dict]]:
    """Every attack against every design. Each row holds one cell per entry in CONFIGS."""
    hack = scenario.index_at(HACK_AT)
    matrix: dict[str, list[dict]] = {}
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        for name, target in TARGETS.items():
            wanted = target(scenario)
            cells = [v1_outcome(wanted, folder)]
            for design in DESIGNS:
                run = record_until_hack(scenario, design, hack)
                cells.append(best_outcome(run, wanted, restamp=name not in TIME_ROWS))
            matrix[name] = cells
        matrix[OLD_PROOF] = [v1_outcome(scenario.messages, folder)] + [
            _old_proof_outcome(scenario, design) for design in DESIGNS
        ]
        matrix[BEFORE_START] = [v1_outcome(_fabricated(scenario), folder)] + [
            _before_start_outcome(scenario, design) for design in DESIGNS
        ]
    return matrix


def _label(cell: dict) -> str:
    seam = cell.get("seam_s")
    if cell["outcome"] == FLAGGED and seam is not None:
        return f"{FLAGGED} (gap {seam:.1f} s)"
    return cell["outcome"]


def findings(matrix: dict[str, list[dict]]) -> list[str]:
    """Cells that differ from EXPECTED."""
    found = []
    for name, cells in matrix.items():
        for config, cell, expected in zip(CONFIGS, cells, EXPECTED[name], strict=True):
            if cell["outcome"] != expected:
                found.append(
                    f"{name} / {config}: expected {expected}, got {cell['outcome']} "
                    f"({cell['strategy']}: {cell['reason']})"
                )
    return found


def synthetic_log() -> list[Message]:
    start = 1_700_000_000 * SECOND
    return [(f"/t{i % 3}", start + i * SECOND // 10, i.to_bytes(4, "big")) for i in range(300)]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--log", type=Path, help="a real log; a synthetic one is used if omitted")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    messages = list(iter_messages(args.log)) if args.log else synthetic_log()
    matrix = run_matrix(Scenario.of(messages))
    width = max(len(name) for name in matrix)
    print(" " * width + "  " + "  ".join(f"{config:<33}" for config in CONFIGS))
    for name, cells in matrix.items():
        print(f"{name:<{width}}  " + "  ".join(f"{_label(cell):<33}" for cell in cells))
    found = findings(matrix)
    print("\nfindings: " + ("none" if not found else ""))
    for line in found:
        print(" - " + line)
    if args.out:
        args.out.write_text(json.dumps({"configs": CONFIGS, "matrix": matrix}, indent=1))


if __name__ == "__main__":
    main()
