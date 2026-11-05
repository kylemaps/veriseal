"""Measure what sealing costs on this machine: time, CPU, memory and, where a sensor exists, energy.

Run it on the robot's own computer with the logs it records:

    python bench/measure.py LOG [LOG ...] --runs 5 --out results.json

Each run executes the real `veriseal seal` (offline, --no-anchor) and `veriseal verify` as
child processes, as a deployment would, and records wall time, CPU time and peak
memory for each. If the machine has a power sensor (Jetson tegrastats or INA3221, the
Raspberry Pi 5 PMIC, Intel RAPL, or a discharging battery), power is sampled while idle
and during every run, and the extra energy used by sealing is reported. Nothing is sent
anywhere and the logs are never modified; seals are written to a temporary folder.

The results file holds timings, sizes, message counts and the machine description, but
no log content. Needs Python 3.11+ with veriseal installed.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

VERISEAL = [sys.executable, "-c", "from veriseal.cli import app; app()"]


# power sources


@dataclass
class PowerSource:
    """Something that reports power in watts (read_w) or an energy counter in joules."""

    name: str
    detail: str
    read_w: object = None  # () -> float, instantaneous power
    read_j: object = None  # () -> float, cumulative energy counter
    stop: object = None  # () -> None, releases a background reader
    interval_s: float = 0.1


# "VDD_IN 4334mW/4334mW" (JetPack 5+) or "POM_5V_IN 2451/2451" (older); the lookahead
# skips memory figures such as "RAM 2843/7620MB", which have the same shape.
_TEGRA_RAIL = re.compile(r"\b([A-Z][A-Z0-9_]*) (\d+)(?:mW)?/(\d+)(?:mW)?(?![\dA-Za-z])")
_TEGRA_TOTALS = ("VDD_IN", "POM_5V_IN", "VIN_SYS_5V0")


def parse_tegrastats(line: str) -> tuple[float, str] | None:
    """Board power in watts from one tegrastats line, and which rail(s) it came from.

    Prefers the board input rail (VDD_IN on Orin/Xavier NX, POM_5V_IN on Nano); on boards
    without one (AGX Xavier) it sums every rail, which misses conversion losses.
    """
    rails = {name: int(now) for name, now, _avg in _TEGRA_RAIL.findall(line)}
    rails = {k: v for k, v in rails.items() if not k.endswith("_FREQ")}
    for total in _TEGRA_TOTALS:
        if total in rails:
            return rails[total] / 1000, total
    if rails:
        return sum(rails.values()) / 1000, "sum of " + "+".join(sorted(rails))
    return None


def parse_pmic_adc(text: str) -> float | None:
    """Raspberry Pi 5 `vcgencmd pmic_read_adc`: sum of current x voltage over every rail."""
    amps = dict(re.findall(r"(\S+)_A current\(\d+\)=([\d.]+)A", text))
    volts = dict(re.findall(r"(\S+)_V volt\(\d+\)=([\d.]+)V", text))
    rails = [float(amps[r]) * float(volts[r]) for r in amps if r in volts]
    return sum(rails) if rails else None


def _tegrastats() -> PowerSource | None:
    exe = shutil.which("tegrastats")
    if exe is None:
        return None
    proc = subprocess.Popen(
        [exe, "--interval", "100"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    latest: dict[str, object] = {}

    def pump() -> None:
        for line in proc.stdout:
            parsed = parse_tegrastats(line)
            if parsed:
                latest["w"], latest["rail"] = parsed

    threading.Thread(target=pump, daemon=True).start()
    deadline = time.monotonic() + 3
    while "w" not in latest and time.monotonic() < deadline:
        time.sleep(0.05)
    if "w" not in latest:
        proc.terminate()
        return None
    return PowerSource(
        "tegrastats",
        f"Jetson board power, rail {latest['rail']}",
        read_w=lambda: latest["w"],
        stop=proc.terminate,
    )


def _ina3221(root: str = "/sys/bus/i2c/drivers/ina3221") -> PowerSource | None:
    """Jetson INA3221 via hwmon: channel N has inN_label, inN_input (mV) and currN_input (mA)."""
    channels = []
    for label_file in glob.glob(f"{root}/*/hwmon/hwmon*/in*_label"):
        n = re.search(r"in(\d+)_label$", label_file).group(1)
        base = os.path.dirname(label_file)
        mv, ma = f"{base}/in{n}_input", f"{base}/curr{n}_input"
        if os.path.exists(mv) and os.path.exists(ma):
            channels.append((Path(label_file).read_text().strip(), mv, ma))
    if not channels:
        return None
    total = [c for c in channels if c[0] in _TEGRA_TOTALS]
    chosen = total[:1] or channels

    def read() -> float:
        return (
            sum(int(Path(mv).read_text()) * int(Path(ma).read_text()) for _, mv, ma in chosen) / 1e6
        )

    rails = "+".join(c[0] for c in chosen)
    return PowerSource("ina3221", f"Jetson INA3221, rail {rails}", read_w=read)


def _pi_pmic() -> PowerSource | None:
    exe = shutil.which("vcgencmd")
    if exe is None:
        return None

    def read() -> float:
        out = subprocess.run([exe, "pmic_read_adc"], capture_output=True, text=True).stdout
        watts = parse_pmic_adc(out)
        if watts is None:
            raise OSError("vcgencmd pmic_read_adc gave no readings")
        return watts

    try:
        read()
    except OSError:
        return None
    return PowerSource(
        "pi-pmic",
        "Raspberry Pi 5 PMIC rails (SoC and RAM; excludes USB and other peripherals)",
        read_w=read,
        interval_s=0.25,
    )


def _rapl(root: str = "/sys/class/powercap/intel-rapl:0") -> PowerSource | None:
    counter = Path(root, "energy_uj")
    try:
        int(counter.read_text())
        wrap = int(Path(root, "max_energy_range_uj").read_text())
    except (OSError, ValueError):
        return None  # absent, or root-only on this kernel (run with sudo to use it)
    state = {"last": int(counter.read_text()), "total": 0}

    def read() -> float:
        now = int(counter.read_text())
        state["total"] += (now - state["last"]) % wrap
        state["last"] = now
        return state["total"] / 1e6

    return PowerSource("rapl", "Intel RAPL CPU package energy counter", read_j=read)


def _battery(root: str = "/sys/class/power_supply") -> PowerSource | None:
    for bat in sorted(glob.glob(f"{root}/BAT*")):
        status = Path(bat, "status")
        if not status.exists() or status.read_text().strip() != "Discharging":
            continue
        if Path(bat, "power_now").exists():
            return PowerSource(
                "battery",
                f"{os.path.basename(bat)} power_now while discharging",
                read_w=lambda b=bat: int(Path(b, "power_now").read_text()) / 1e6,
            )
        if Path(bat, "current_now").exists() and Path(bat, "voltage_now").exists():
            return PowerSource(
                "battery",
                f"{os.path.basename(bat)} current_now x voltage_now while discharging",
                read_w=lambda b=bat: (
                    int(Path(b, "current_now").read_text())
                    * int(Path(b, "voltage_now").read_text())
                    / 1e12
                ),
            )
    return None


def find_power_source(choice: str) -> PowerSource | None:
    finders = {
        "tegrastats": _tegrastats,
        "ina3221": _ina3221,
        "pi-pmic": _pi_pmic,
        "rapl": _rapl,
        "battery": _battery,
    }
    if choice == "none":
        return None
    order = [choice] if choice != "auto" else list(finders)
    for name in order:
        source = finders[name]()
        if source is not None:
            return source
    return None


class PowerMeter:
    """Samples a PowerSource in the background between start() and stop()."""

    def __init__(self, source: PowerSource) -> None:
        self.source = source
        self._samples: list[float] = []
        self._running = False

    def _loop(self) -> None:
        while self._running:
            try:
                self._samples.append(self.source.read_w())
            except (OSError, ValueError):
                pass
            time.sleep(self.source.interval_s)

    def start(self) -> None:
        if self.source.read_j is not None:
            self._j0, self._t0 = self.source.read_j(), time.monotonic()
            return
        self._samples, self._running = [], True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> dict:
        """Mean power (W) over the window, and how many samples it rests on."""
        if self.source.read_j is not None:
            joules, secs = self.source.read_j() - self._j0, time.monotonic() - self._t0
            return {"mean_w": joules / secs if secs > 0 else None, "samples": None}
        self._running = False
        self._thread.join()
        if not self._samples:
            return {"mean_w": None, "samples": 0}
        return {"mean_w": statistics.fmean(self._samples), "samples": len(self._samples)}


# running veriseal


@dataclass
class Run:
    wall_s: float
    cpu_s: float | None
    peak_rss_mb: float | None
    mean_w: float | None = None
    power_samples: int | None = None
    extra: dict = field(default_factory=dict)


def run_measured(args: list[str], meter: PowerMeter | None) -> Run:
    """Run veriseal with *args* as a child process; time it and read its own resource usage."""
    if meter:
        meter.start()
    t0 = time.perf_counter()
    proc = subprocess.Popen(VERISEAL + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if hasattr(os, "wait4"):
        out = proc.stdout.read()
        _, status, usage = os.wait4(proc.pid, 0)
        wall = time.perf_counter() - t0
        proc.returncode = os.waitstatus_to_exitcode(status)
        cpu = usage.ru_utime + usage.ru_stime
        rss = usage.ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)
    else:  # Windows: wall time only (no per-child CPU or peak memory without extra packages)
        out, _ = proc.communicate()
        wall, cpu, rss = time.perf_counter() - t0, None, None
    power = meter.stop() if meter else {}
    if proc.returncode not in (0,):
        raise RuntimeError(
            f"veriseal {' '.join(args[:1])} exited {proc.returncode}:\n{out.decode()}"
        )
    return Run(wall, cpu, rss, power.get("mean_w"), power.get("samples"))


def idle_power(meter: PowerMeter, seconds: float) -> float | None:
    meter.start()
    time.sleep(seconds)
    return meter.stop()["mean_w"]


def log_files(paths: list[str]) -> list[Path]:
    """Expand ROS 2 bag folders to the .mcap files inside them."""
    found: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            found += sorted(p.glob("*.mcap"))
            if any(p.glob("*.db3")) and not any(p.glob("*.mcap")):
                sys.exit(
                    f"{p} is a SQLite (.db3) bag; record with --storage mcap or convert it first"
                )
        else:
            found.append(p)
    return found


def machine() -> dict:
    info = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpus": os.cpu_count(),
        "python": platform.python_version(),
    }
    try:
        from veriseal import __version__

        info["veriseal"] = __version__
    except ImportError:
        pass
    for key, path in (
        ("model", "/proc/device-tree/model"),
        ("cpu_governor", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
    ):
        try:
            info[key] = Path(path).read_text().strip("\x00\n ")
        except OSError:
            pass
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text()
        m = re.search(r"^model name\s*:\s*(.+)$", cpuinfo, re.M)
        if m:
            info["cpu"] = m.group(1)
        mem = re.search(r"^MemTotal:\s*(\d+) kB", Path("/proc/meminfo").read_text(), re.M)
        if mem:
            info["ram_gb"] = round(int(mem.group(1)) / 1024**2, 1)
    except OSError:
        info["cpu"] = platform.processor()
    if shutil.which("nvpmodel"):
        q = subprocess.run(["nvpmodel", "-q"], capture_output=True, text=True).stdout
        info["nvpmodel"] = " ".join(q.split())
    return info


def _med(values: list) -> float | None:
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def summarise(runs: list[Run], idle_w: float | None) -> dict:
    out = {
        "wall_s": _med([r.wall_s for r in runs]),
        "cpu_s": _med([r.cpu_s for r in runs]),
        "peak_rss_mb": _med([r.peak_rss_mb for r in runs]),
        "mean_w": _med([r.mean_w for r in runs]),
    }
    if out["mean_w"] is not None:
        out["energy_j"] = out["mean_w"] * out["wall_s"]
        if idle_w is not None:
            out["extra_energy_j"] = max(out["mean_w"] - idle_w, 0.0) * out["wall_s"]
    return out


def measure(argv: list[str] | None = None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("logs", nargs="+", help=".mcap or .bag files, or ROS 2 bag folders")
    ap.add_argument("--runs", type=int, default=5, help="seal + verify runs per log (default 5)")
    ap.add_argument("--out", default="veriseal-measurements.json", help="results file")
    ap.add_argument(
        "--power",
        default="auto",
        choices=["auto", "tegrastats", "ina3221", "pi-pmic", "rapl", "battery", "none"],
        help="power sensor to use (default: the first one found)",
    )
    ap.add_argument("--idle-seconds", type=float, default=10, help="idle power window (default 10)")
    ap.add_argument("--battery-wh", type=float, help="robot battery capacity, for a %% figure")
    args = ap.parse_args(argv)

    logs = log_files(args.logs)
    source = find_power_source(args.power)
    meter = PowerMeter(source) if source else None
    result = {
        "machine": machine(),
        "power_source": {"name": source.name, "detail": source.detail} if source else None,
        "runs_per_log": args.runs,
        "logs": [],
    }
    work = Path(tempfile.mkdtemp(prefix="veriseal-measure-"))
    try:
        key, pub = work / "signer.key.pem", work / "signer.pub.pem"
        run_measured(["keygen", "--out", str(key), "--pub", str(pub)], None)
        startup = [run_measured(["--help"], None) for _ in range(3)]
        result["startup"] = summarise(startup, None)
        idle_w = idle_power(meter, args.idle_seconds) if meter else None
        result["idle_w"] = idle_w

        for log in logs:
            seal_path = work / (log.name + ".seal.json")
            seals, verifies = [], []
            for _ in range(args.runs):
                seal_path.unlink(missing_ok=True)
                seals.append(
                    run_measured(
                        [
                            "seal",
                            str(log),
                            "--key",
                            str(key),
                            "--no-anchor",
                            "--out",
                            str(seal_path),
                        ],
                        meter,
                    )
                )
                verifies.append(
                    run_measured(["verify", str(log), str(seal_path), "--pubkey", str(pub)], meter)
                )
            manifest = json.loads(seal_path.read_bytes())
            messages = manifest["messages"]
            duration_s = (messages["log_time_max"] - messages["log_time_min"]) / 1e9
            entry = {
                "file": log.name,
                "bytes": log.stat().st_size,
                "messages": messages["count"],
                "log_duration_s": duration_s,
                "seal_json_bytes": seal_path.stat().st_size,
                "seal": summarise(seals, idle_w),
                "verify": summarise(verifies, idle_w),
                "seal_runs": [vars(r) for r in seals],
                "verify_runs": [vars(r) for r in verifies],
            }
            extra = entry["seal"].get("extra_energy_j")
            if extra is not None and duration_s > 0:
                entry["seal_extra_j_per_hour_of_log"] = extra * 3600 / duration_s
                if args.battery_wh:
                    entry["seal_battery_pct_per_hour_of_log"] = (
                        100 * extra * 3600 / duration_s / (args.battery_wh * 3600)
                    )
            result["logs"].append(entry)
            print(_line(entry), flush=True)
    finally:
        if source and source.stop:
            source.stop()
        shutil.rmtree(work, ignore_errors=True)

    Path(args.out).write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    print(f"\nWrote {args.out}. Please send this file back; it holds no log content.")
    return result


def _line(entry: dict) -> str:
    s, v = entry["seal"], entry["verify"]
    parts = [
        f"{entry['file']}: {entry['messages']} messages, {entry['bytes'] / 1e6:.1f} MB",
        f"seal {s['wall_s']:.2f} s",
        f"verify {v['wall_s']:.2f} s",
    ]
    if s["cpu_s"] is not None:
        parts.append(f"seal CPU {s['cpu_s']:.2f} s, peak {s['peak_rss_mb']:.0f} MB")
    if "extra_energy_j" in s:
        parts.append(f"seal extra energy {s['extra_energy_j']:.1f} J")
    return " | ".join(parts)


if __name__ == "__main__":
    measure()
