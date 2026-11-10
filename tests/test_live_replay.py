"""bench/live_replay.py: the parts that need no ROS (order, counting, summaries)."""

from __future__ import annotations

import json
import os

import pytest
from mcap.writer import Writer

from tests.test_bench_measure import REPO, _load

live = _load("live_replay", REPO / "bench" / "live_replay.py")
SECOND = 1_000_000_000


def _bag(folder, messages, **options):
    folder.mkdir()
    with open(folder / "task_0.mcap", "wb") as file:
        writer = Writer(file, **options)
        writer.start()
        schema = writer.register_schema(name="raw", encoding="", data=b"")
        channels: dict[str, int] = {}
        for topic, log_time in messages:
            if topic not in channels:
                channels[topic] = writer.register_channel(topic, "", schema)
            writer.add_message(channels[topic], log_time=log_time, data=b"x", publish_time=log_time)
        writer.finish()
    return folder


MESSAGES = [("/tf", i * SECOND // 10) for i in range(30)] + [("/odom", 5 * SECOND)]


def test_each_repeat_starts_with_the_next_setup():
    setups = ["A", "B", "C"]
    assert [live.rotation(repeat, setups) for repeat in range(4)] == [
        ["A", "B", "C"],
        ["B", "C", "A"],
        ["C", "A", "B"],
        ["A", "B", "C"],
    ]


@pytest.mark.parametrize("statistics", [True, False])
def test_topics_are_counted_with_or_without_a_summary(tmp_path, statistics):
    bag = _bag(tmp_path / "bag", MESSAGES, use_statistics=statistics)
    assert live.topic_counts(bag) == {"/tf": 30, "/odom": 1}


def test_the_bag_plays_from_its_first_message_to_its_last(tmp_path):
    assert live.bag_seconds(_bag(tmp_path / "bag", MESSAGES)) == 5.0


def test_extra_energy_is_paired_within_each_repeat():
    rows = [
        {"repeat": r, "setup": s, "energy_j": e, "dropped": {}, "verified": True}
        for r, energies in enumerate([(100, 103, 110), (120, 124, 129), (90, 92, 101)])
        for s, e in zip("ABC", energies, strict=True)
    ]
    summary = live.summarise(rows, ["A", "B", "C"])
    assert summary["A"]["energy_j_mean"] == pytest.approx(310 / 3)
    assert summary["B-A"]["extra_energy_j"] == pytest.approx(3.0)
    assert summary["C-B"]["extra_energy_j"] == pytest.approx(7.0)
    assert summary["B-A"]["pairs"] == 3 and summary["B"]["all_verified"]


def test_runs_without_energy_still_summarise():
    rows = [{"repeat": 0, "setup": s, "energy_j": None, "dropped": {"/tf": 2}} for s in "AB"]
    summary = live.summarise(rows, ["A", "B"])
    assert summary["A"]["energy_j_mean"] is None and summary["A"]["dropped_mean"] == 2
    assert "B-A" not in summary


def test_a_topic_never_recorded_is_named_not_counted_as_drops():
    row = {
        "repeat": 0,
        "setup": "A",
        "window_s": 82.0,
        "energy_j": None,
        "mean_w": None,
        "dropped": {"/tf": 3},
        "recorded": 900,
        "never_recorded": ["/arm/state"],
    }
    line = live._line(row)
    assert "dropped 3" in line and "never recorded" in line and "/arm/state" in line


def test_deliveries_are_summed_up(tmp_path):
    path = tmp_path / "deliveries.jsonl"
    events = [
        {"event": "start", "outcome": "delivered"},
        {"event": "head", "outcome": "lost", "closed_ns": 0},
        {"event": "head", "outcome": "delivered", "closed_ns": 0, "delivered_ns": 4_000_000},
        {"event": "head", "outcome": "delivered", "closed_ns": 0, "delivered_ns": 2_000_000},
    ]
    path.write_text("".join(json.dumps(event) + "\n" for event in events))
    assert live.deliveries(path) == {
        "attempts": 3,
        "delivered": 2,
        "lost": 1,
        "wait_p50_ms": 4.0,
        "wait_max_ms": 4.0,
    }
    assert live.deliveries(tmp_path / "missing.jsonl") is None


@pytest.mark.parametrize(
    ("distro", "switch"),
    [("humble", "ROS_LOCALHOST_ONLY"), ("jazzy", "ROS_AUTOMATIC_DISCOVERY_RANGE")],
)
def test_the_replay_stays_on_its_own_domain_and_this_computer(monkeypatch, distro, switch):
    monkeypatch.setenv("ROS_DISTRO", distro)
    env = live.ros_environment(87)
    assert env["ROS_DOMAIN_ID"] == "87"
    assert env[switch] in ("1", "LOCALHOST")


def test_the_sealer_runs_without_ros_python_packages():
    paths = os.pathsep.join(["/opt/ros/humble/lib/python3.10/site-packages", "/src/src"])
    env = {"PYTHONPATH": paths, "HOME": "/root"}
    assert live._without_ros_python(env) == {"PYTHONPATH": "/src/src", "HOME": "/root"}
