"""Compare what was played with what was recorded and sealed, for one run of replay.sh."""

import json
import statistics
import sys
from collections import Counter
from pathlib import Path

from mcap.reader import make_reader

out, name, grace, options = Path(sys.argv[1]), sys.argv[2], float(sys.argv[3]), sys.argv[4]


def count(path: Path):
    topics: Counter = Counter()
    with open(path, "rb") as f:
        reader = make_reader(f)
        summary = reader.get_summary()
        for _, channel, _ in reader.iter_messages():
            topics[channel.topic] += 1
    return topics, summary


def text(path: Path) -> str | None:
    return path.read_text().strip() if path.exists() else None


played, _ = count(Path("/work/ros2bag") / next(Path("/work/ros2bag").glob("*.mcap")).name)
recorded, summary = count(out / "rec" / "rec_0.mcap")
chunks = summary.chunk_indexes if summary else []
spans = [(c.message_end_time - c.message_start_time) / 1e9 for c in chunks]
stats_path = out / "sealed" / "stats.json"
stats = json.loads(stats_path.read_text()) if stats_path.exists() else {}
report = {
    "run": name,
    "recorder_options": options,
    "grace_s": grace,
    "played": sum(played.values()),
    "recorded": sum(recorded.values()),
    "missing_by_topic": {t: played[t] - recorded[t] for t in played if played[t] != recorded[t]},
    "sealed": stats.get("messages"),
    "late": stats.get("late"),
    "verify": text(out / "verify.log"),
    "verify_after_convert": text(out / "convert-verify.log"),
    "chunks": len(chunks),
    "compression": sorted({c.compression for c in chunks}),
    "chunk_kib_median": statistics.median(c.uncompressed_size for c in chunks) / 1024
    if chunks
    else None,
    "chunk_span_s_median": statistics.median(spans) if spans else None,
    "file_mb": (out / "rec" / "rec_0.mcap").stat().st_size / 1e6,
    "read_delay": stats.get("read_delay"),
    "head_delay": stats.get("head_delay"),
    "sealer_cpu_s": stats.get("cpu_s"),
    "sealer_wall_s": stats.get("wall_s"),
    "finished": stats.get("finished"),
}
(out / "report.json").write_text(json.dumps(report, indent=1))
print(json.dumps(report, indent=1))
