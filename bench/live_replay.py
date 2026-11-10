"""Replay a recorded task through the real ROS 2 recorder, with and without sealing, measuring each.

    source /opt/ros/humble/setup.bash
    python bench/live_replay.py TASK_BAG --out live.json \
        --witness http://LAB-PC:8787 --witness-pub witness.pub.pem

TASK_BAG is a ROS 2 bag folder holding MCAP files. ``ros2 bag play`` stands in for the robot's
sensors, and ``ros2 bag record`` records as it would during a task. Three setups take turns, in
a rotating order, so slow drift in the machine's power affects all three alike:

    A  record only
    B  record, with the sealer reading the file as it grows (python -m veriseal.tail)
    C  as B, with each head sent to a witness on another machine

Every run is measured over the same fixed time, so the differences in energy between setups are
the cost of sealing (B - A) and of sending (C - B). Each run also reports how many messages the
recorder dropped, how far behind the recorder the sealer ran, and whether the result verifies.
C needs --witness and --witness-pub; without them only A and B run.

The player and the recorder run on their own ROS domain (--domain-id) and stay on this computer,
because the replay publishes the task's motion commands and must never reach the robot's own
nodes. Keep the motors off all the same.

The energy comes from the sources bench/measure.py knows. On the NUC that is Intel RAPL, which
recent kernels let only root read; run ``sudo chmod a+r /sys/class/powercap/intel-rapl:0/energy_uj``
once per boot, or the runs go ahead without energy. Recordings are deleted after each run, and
the results file holds counts, times and energy, nothing from inside the log.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shlex
import shutil
import signal
import statistics
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from mcap.reader import make_reader

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure import PowerMeter, find_power_source, idle_power, machine  # noqa: E402

SETUPS = {
    "A": "record only",
    "B": "record and seal",
    "C": "record, seal and send each head to the witness",
}
PLAY_DELAY_S = 3  # the player waits this long, so the recorder subscribes before the first message
SETTLE_S = 2
SECOND = 1_000_000_000


def topic_counts(folder: Path) -> dict[str, int]:
    """Messages per topic in a bag folder's MCAP files, from their summaries where they have one."""
    counts: Counter = Counter()
    for path in sorted(folder.glob("*.mcap")):
        with open(path, "rb") as file:
            reader = make_reader(file)
            summary = reader.get_summary()
            statistics_ = summary.statistics if summary else None
            if statistics_ and statistics_.channel_message_counts:
                for channel, count in statistics_.channel_message_counts.items():
                    counts[summary.channels[channel].topic] += count
                continue
            for _, channel, _ in reader.iter_messages():
                counts[channel.topic] += 1
    return dict(counts)


def bag_seconds(folder: Path) -> float:
    """How long a bag folder plays, from its first message to its last."""
    first = last = None
    for path in folder.glob("*.mcap"):
        with open(path, "rb") as file:
            summary = make_reader(file).get_summary()
        if summary is None or summary.statistics is None:
            raise ValueError(f"{path.name} has no summary; was the recording finished properly?")
        start, end = summary.statistics.message_start_time, summary.statistics.message_end_time
        first = start if first is None else min(first, start)
        last = end if last is None else max(last, end)
    if first is None or last is None:
        raise ValueError(f"no MCAP files in {folder}")
    return (last - first) / SECOND


def ros_environment(domain_id: int) -> dict[str, str]:
    """Environment for the player and the recorder: their own ROS domain, on this computer only.

    The replay publishes the task's topics, motion commands included, so it must never reach
    the robot's own nodes.
    """
    env = dict(os.environ, ROS_DOMAIN_ID=str(domain_id))
    if os.environ.get("ROS_DISTRO", "") in ("foxy", "galactic", "humble"):
        env["ROS_LOCALHOST_ONLY"] = "1"
    else:  # Iron and later replaced that switch
        env["ROS_AUTOMATIC_DISCOVERY_RANGE"] = "LOCALHOST"
        env.pop("ROS_LOCALHOST_ONLY", None)
    return env


def rotation(repeat: int, setups: list[str]) -> list[str]:
    """The order for one repeat: ABC, then BCA, then CAB, so no setup always goes first."""
    shift = repeat % len(setups)
    return setups[shift:] + setups[:shift]


def _without_ros_python(env: dict[str, str]) -> dict[str, str]:
    """The sealer runs on its own newer Python, so keep ROS's Python packages off its path."""
    paths = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p and "/opt/ros/" not in p]
    return {**env, "PYTHONPATH": os.pathsep.join(paths)}


def deliveries(path: Path) -> dict | None:
    """Sums up a sealer's deliveries.jsonl: attempts, outcomes, and how long heads took to land."""
    if not path.exists():
        return None
    events = [json.loads(line) for line in path.read_text().splitlines() if line]
    heads = [event for event in events if event.get("event") == "head"]
    landed = [event for event in heads if event.get("outcome") == "delivered"]
    waits = sorted(event["delivered_ns"] - event["closed_ns"] for event in landed)
    return {
        "attempts": len(heads),
        "delivered": len(landed),
        "lost": sum(event.get("outcome") == "lost" for event in heads),
        "wait_p50_ms": waits[len(waits) // 2] / 1e6 if waits else None,
        "wait_max_ms": waits[-1] / 1e6 if waits else None,
    }


def _stop(process: subprocess.Popen | None, wait_s: float) -> None:
    """Ask a process to finish as Ctrl-C would, and make sure it is gone."""
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=wait_s)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def run_setup(
    setup: str,
    repeat: int,
    args: argparse.Namespace,
    played: dict[str, int],
    window_s: float,
    meter: PowerMeter | None,
) -> dict:
    """One replay in one setup, measured over a window of *window_s* seconds."""
    from veriseal.tail import check_sealed

    folder = args.work / f"{repeat:02d}-{setup}"
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    recording, sealed = folder / "rec", folder / "sealed"
    sealer = recorder = None
    power: dict = {}
    with open(folder / "processes.log", "w") as log:
        if meter:
            meter.start()
        began = time.monotonic()
        try:
            if setup in ("B", "C"):
                command = [
                    sys.executable, "-m", "veriseal.tail", "seal", str(recording / "rec_0.mcap"),
                    "--out-dir", str(sealed),
                    "--epoch-seconds", str(args.epoch_seconds),
                    "--grace-seconds", str(args.grace_seconds),
                    "--max-seconds", str(window_s + 600),
                ]  # fmt: skip
                if setup == "C":
                    command += ["--witness", args.witness, "--witness-pub", str(args.witness_pub)]
                    command += ["--export-every", str(args.export_every)]
                sealer = subprocess.Popen(
                    command,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    env=_without_ros_python(dict(os.environ)),
                    start_new_session=True,
                )
            isolated = ros_environment(args.domain_id)
            recorder = subprocess.Popen(
                ["ros2", "bag", "record", "-s", "mcap", "-o", str(recording)]
                + shlex.split(args.record_args)
                + sorted(played),
                stdout=log,
                stderr=subprocess.STDOUT,
                env=isolated,
                start_new_session=True,
            )
            time.sleep(SETTLE_S)
            play = ["ros2", "bag", "play", "-s", "mcap", str(args.bag)]
            play += ["--delay", str(PLAY_DELAY_S)]
            subprocess.run(play, stdout=log, stderr=subprocess.STDOUT, env=isolated, check=False)
            time.sleep(SETTLE_S)
            _stop(recorder, 120)
            if sealer:
                try:
                    sealer.wait(timeout=60)  # it stops by itself once the recording is closed
                except subprocess.TimeoutExpired:
                    _stop(sealer, 30)
            while (left := began + window_s - time.monotonic()) > 0:
                time.sleep(min(left, 0.5))
            elapsed = time.monotonic() - began
        finally:
            _stop(recorder, 30)
            _stop(sealer, 30)
            if meter:
                power = meter.stop()
    mean_w = power.get("mean_w")
    recorded = topic_counts(recording)
    row: dict = {
        "repeat": repeat,
        "setup": setup,
        "window_s": round(elapsed, 3),
        "over_window": elapsed > window_s + 1,
        "mean_w": mean_w,
        "energy_j": mean_w * elapsed if mean_w is not None else None,
        "played": sum(played.values()),
        "recorded": sum(recorded.values()),
        # A topic with nothing recorded at all was never replayed, most likely because its
        # message type isn't installed here. That's a setup problem, not dropped messages.
        "never_recorded": sorted(topic for topic in played if not recorded.get(topic)),
        "dropped": {
            topic: count - recorded[topic]
            for topic, count in played.items()
            if recorded.get(topic) and count != recorded[topic]
        },
    }
    if sealer:
        stats_path = sealed / "stats.json"
        stats = json.loads(stats_path.read_text()) if stats_path.exists() else {}
        result = check_sealed(recording / "rec_0.mcap", sealed)
        row |= {
            "verified": result.ok,
            "verify_reason": result.reason,
            "sealed": stats.get("messages"),
            "late": stats.get("late"),
            "read_delay": stats.get("read_delay"),
            "head_delay": stats.get("head_delay"),
            "sealer_cpu_s": stats.get("cpu_s"),
            "deliveries": deliveries(sealed / "deliveries.jsonl"),
        }
    shutil.rmtree(recording, ignore_errors=True)  # keep the disk from filling over many runs
    (sealed / "leaves.bin").unlink(missing_ok=True)
    return row


# Two-sided 95% points of the t distribution for 1 to 30 degrees of freedom.
_T95 = (
    12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
    2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
    2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042,
)  # fmt: skip


def _t95(freedom: int) -> float:
    return _T95[freedom - 1] if freedom <= len(_T95) else 1.96


def summarise(rows: list[dict], setups: list[str]) -> dict:
    """Mean energy per setup, and the extra energy of each step paired within each repeat."""
    summary: dict = {}
    for setup in setups:
        mine = [row for row in rows if row["setup"] == setup]
        energy = [row["energy_j"] for row in mine if row["energy_j"] is not None]
        dropped = [sum(row["dropped"].values()) for row in mine]
        summary[setup] = {
            "runs": len(mine),
            "energy_j_mean": statistics.fmean(energy) if energy else None,
            "energy_j_sd": statistics.stdev(energy) if len(energy) > 1 else None,
            "dropped_mean": statistics.fmean(dropped) if dropped else None,
            "all_verified": all(row.get("verified", True) for row in mine),
        }
    by_repeat: dict[int, dict[str, float | None]] = {}
    for row in rows:
        by_repeat.setdefault(row["repeat"], {})[row["setup"]] = row["energy_j"]
    for before, after in (("A", "B"), ("B", "C")):
        pairs = [
            energies[after] - energies[before]
            for energies in by_repeat.values()
            if energies.get(before) is not None and energies.get(after) is not None
        ]
        if pairs:
            spread = (
                _t95(len(pairs) - 1) * statistics.stdev(pairs) / math.sqrt(len(pairs))
                if len(pairs) > 1
                else None
            )
            summary[f"{after}-{before}"] = {
                "extra_energy_j": statistics.fmean(pairs),
                "ci95_j": spread,  # half-width, t distribution
                "pairs": len(pairs),
            }
    return summary


def _line(row: dict) -> str:
    energy = f"{row['energy_j']:.1f} J ({row['mean_w']:.2f} W)" if row["energy_j"] else "no energy"
    text = (
        f"repeat {row['repeat'] + 1:2} {row['setup']}: {row['window_s']:.0f} s, {energy}, "
        f"dropped {sum(row['dropped'].values())}"
    )
    if row["recorded"] == 0:
        text += ", NOTHING recorded: see processes.log in the work folder"
    elif row.get("never_recorded"):
        text += (
            f", never recorded (is the message type installed?): {' '.join(row['never_recorded'])}"
        )
    if "verified" in row:
        head = (row.get("head_delay") or {}).get("p50_ms")
        delay = f", heads {head:.0f} ms behind" if head is not None else ""
        text += (
            f"{delay}, {'verified' if row['verified'] else 'NOT verified: ' + row['verify_reason']}"
        )
    return text


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("bag", type=Path, help="a recorded task: a ROS 2 bag folder of MCAP files")
    parser.add_argument("--repeats", type=int, default=25)
    parser.add_argument("--setups", default="A,B,C")
    parser.add_argument("--witness", help="witness URL, for setup C")
    parser.add_argument("--witness-pub", type=Path, help="the witness's public key (PEM)")
    parser.add_argument("--export-every", type=int, default=1, help="send every Nth head")
    parser.add_argument(
        "--record-args",
        default="--storage-preset-profile fastwrite",
        help="options for ros2 bag record (default: write without chunks)",
    )
    parser.add_argument("--epoch-seconds", type=float, default=1.0)
    parser.add_argument("--grace-seconds", type=float, default=6.0)
    parser.add_argument(
        "--domain-id", type=int, default=87, help="ROS domain for the replay, away from the robot's"
    )
    parser.add_argument(
        "--power",
        default="auto",
        choices=["auto", "tegrastats", "ina3221", "pi-pmic", "rapl", "battery", "none"],
    )
    parser.add_argument(
        "--idle-seconds", type=float, default=30.0, help="idle power, before and after"
    )
    parser.add_argument("--work", type=Path, default=Path("live-replay-work"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    setups = [name.strip().upper() for name in args.setups.split(",") if name.strip()]
    if any(name not in SETUPS for name in setups):
        parser.error("setups are A, B and C")
    if "C" in setups and not (args.witness and args.witness_pub):
        print("no --witness and --witness-pub, so setup C is left out", flush=True)
        setups.remove("C")
    if shutil.which("ros2") is None:
        parser.error("ros2 not found: source your ROS 2 setup first")
    mcap_plugin = ["ros2", "pkg", "prefix", "rosbag2_storage_mcap"]
    if subprocess.run(mcap_plugin, capture_output=True).returncode != 0:
        parser.error(
            "the recorder can't write MCAP here. Install its plugin: "
            "sudo apt install ros-$ROS_DISTRO-rosbag2-storage-mcap"
        )
    played = topic_counts(args.bag)
    window_s = bag_seconds(args.bag) + PLAY_DELAY_S + 2 * SETTLE_S + 10
    source = find_power_source(args.power)
    meter = PowerMeter(source) if source else None
    minutes = args.repeats * len(setups) * (window_s + 5) / 60
    print(
        f"{args.repeats} repeats of {', '.join(setups)}, {window_s:.0f} s each: about "
        f"{minutes:.0f} minutes. Energy from: {source.detail if source else 'nothing found'}",
        flush=True,
    )
    report: dict = {
        "machine": machine(),
        "ros_distro": os.environ.get("ROS_DISTRO"),
        "power_source": source.detail if source else None,
        "settings": {
            "bag": args.bag.name,
            "setups": {name: SETUPS[name] for name in setups},
            "record_args": args.record_args,
            "epoch_s": args.epoch_seconds,
            "grace_s": args.grace_seconds,
            "export_every": args.export_every,
            "window_s": window_s,
        },
        "idle_w_before": idle_power(meter, args.idle_seconds) if meter else None,
        "runs": [],
    }
    for repeat in range(args.repeats):
        for setup in rotation(repeat, setups):
            row = run_setup(setup, repeat, args, played, window_s, meter)
            report["runs"].append(row)
            print(_line(row), flush=True)
            args.out.write_text(json.dumps(report, indent=1))  # saved as it goes
    report["idle_w_after"] = idle_power(meter, args.idle_seconds) if meter else None
    report["summary"] = summarise(report["runs"], setups)
    args.out.write_text(json.dumps(report, indent=1))
    for name, values in report["summary"].items():
        print(f"{name}: {json.dumps(values)}")


if __name__ == "__main__":
    main()
