"""bench/measure.py: power-sensor parsing, energy arithmetic, and one real offline run."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


measure = _load("measure", REPO / "bench" / "measure.py")

ORIN = (
    "10-27-2023 10:15:42 RAM 2843/7620MB (lfb 1x4MB) SWAP 0/3810MB (cached 0MB) "
    "CPU [2%@729,1%@729,off,off] EMC_FREQ 0%@2133 GR3D_FREQ 0%@[305] VIC_FREQ 729 APE 174 "
    "CPU@46.093C tj@46.093C VDD_IN 4334mW/4334mW VDD_CPU_GPU_CV 556mW/556mW VDD_SOC 1350mW/1350mW"
)
NANO = (
    "RAM 1503/3956MB (lfb 4x4MB) SWAP 0/1978MB (cached 0MB) IRAM 0/252kB(lfb 252kB) "
    "CPU [9%@102,5%@102,4%@102,3%@102] EMC_FREQ 0%@1600 GR3D_FREQ 0%@76 APE 25 "
    "PLL@28C CPU@31C POM_5V_IN 2451/2451 POM_5V_GPU 0/0 POM_5V_CPU 397/397"
)
AGX_XAVIER = (
    "RAM 1903/31927MB (lfb 7068x4MB) SWAP 0/15963MB (cached 0MB) CPU [1%@1190,off] "
    "EMC_FREQ 0% GR3D_FREQ 0% AO@31.5C GPU@31C PMIC@100C GPU 0/0 CPU 155/155 SOC 1240/1240 "
    "CV 0/0 VDDRQ 310/310 SYS5V 2059/2059"
)
PI5_PMIC = """\
     3V3_SYS_A current(1)=0.05000000A
       VDD_CORE_A current(7)=1.00000000A
     3V3_SYS_V volt(9)=3.30000000V
       VDD_CORE_V volt(15)=0.80000000V
        EXT5V_V volt(24)=5.13600400V
"""


@pytest.mark.parametrize(
    ("line", "watts", "rail"),
    [
        (ORIN, 4.334, "VDD_IN"),
        (NANO, 2.451, "POM_5V_IN"),
        (AGX_XAVIER, 3.764, "sum of CPU+CV+GPU+SOC+SYS5V+VDDRQ"),
    ],
)
def test_tegrastats_board_power(line: str, watts: float, rail: str) -> None:
    assert measure.parse_tegrastats(line) == pytest.approx((watts, rail))


def test_tegrastats_ignores_memory_figures() -> None:
    assert measure.parse_tegrastats("RAM 2843/7620MB SWAP 0/3810MB IRAM 0/252kB") is None


def test_pi5_pmic_sums_current_times_voltage() -> None:
    assert measure.parse_pmic_adc(PI5_PMIC) == pytest.approx(0.05 * 3.3 + 1.0 * 0.8)
    assert measure.parse_pmic_adc("") is None


def test_ina3221_prefers_the_board_input_rail(tmp_path: Path) -> None:
    hwmon = tmp_path / "1-0040" / "hwmon" / "hwmon3"
    hwmon.mkdir(parents=True)
    for n, label, mv, ma in [(1, "VDD_IN", 5000, 800), (2, "VDD_SOC", 5000, 200)]:
        (hwmon / f"in{n}_label").write_text(label + "\n")
        (hwmon / f"in{n}_input").write_text(str(mv))
        (hwmon / f"curr{n}_input").write_text(str(ma))
    source = measure._ina3221(str(tmp_path))
    assert "VDD_IN" in source.detail
    assert source.read_w() == pytest.approx(4.0)


def test_rapl_counter_handles_wraparound(tmp_path: Path) -> None:
    (tmp_path / "energy_uj").write_text("900000")
    (tmp_path / "max_energy_range_uj").write_text("1000000")
    source = measure._rapl(str(tmp_path))
    (tmp_path / "energy_uj").write_text("100000")  # wrapped: +200000 uJ
    assert source.read_j() == pytest.approx(0.2)


def test_battery_only_while_discharging(tmp_path: Path) -> None:
    bat = tmp_path / "BAT0"
    bat.mkdir()
    (bat / "power_now").write_text("7500000")
    (bat / "status").write_text("Charging\n")
    assert measure._battery(str(tmp_path)) is None
    (bat / "status").write_text("Discharging\n")
    assert measure._battery(str(tmp_path)).read_w() == pytest.approx(7.5)


def test_extra_energy_is_above_idle() -> None:
    runs = [measure.Run(wall_s=2.0, cpu_s=1.5, peak_rss_mb=80.0, mean_w=10.0)]
    summary = measure.summarise(runs, idle_w=4.0)
    assert summary["energy_j"] == pytest.approx(20.0)
    assert summary["extra_energy_j"] == pytest.approx(12.0)


def test_ros2_bag_folders_expand_to_their_mcap(tmp_path: Path) -> None:
    bag = tmp_path / "run1"
    bag.mkdir()
    (bag / "run1_0.mcap").write_bytes(b"")
    (bag / "metadata.yaml").write_text("")
    assert measure.log_files([str(bag)]) == [bag / "run1_0.mcap"]
    sqlite_bag = tmp_path / "run2"
    sqlite_bag.mkdir()
    (sqlite_bag / "run2_0.db3").write_bytes(b"")
    with pytest.raises(SystemExit, match="db3"):
        measure.log_files([str(sqlite_bag)])


def test_one_offline_run_end_to_end(tmp_path: Path) -> None:
    make_sample = _load("make_sample", REPO / "demo" / "make_sample.py")
    log = tmp_path / "log.mcap"
    make_sample.write_sample(log)
    out = tmp_path / "results.json"
    args = [str(log), "--runs", "1", "--idle-seconds", "0", "--power", "none", "--out", str(out)]
    measure.measure(args)
    result = json.loads(out.read_text(encoding="utf-8"))
    entry = result["logs"][0]
    assert entry["messages"] == 198
    assert entry["seal"]["wall_s"] > 0 and entry["verify"]["wall_s"] > 0
    assert result["power_source"] is None
    assert "log.mcap" in entry["file"] and str(tmp_path) not in json.dumps(result)


def test_stream_mode_reports_checkpoints(tmp_path: Path) -> None:
    make_sample = _load("make_sample", REPO / "demo" / "make_sample.py")
    log = tmp_path / "log.mcap"
    make_sample.write_sample(log)
    out = tmp_path / "results.json"
    args = [str(log), "--runs", "1", "--idle-seconds", "0", "--power", "none", "--out", str(out)]
    measure.measure(args + ["--stream", "1,0.5"])
    stream = json.loads(out.read_text(encoding="utf-8"))["logs"][0]["stream"]
    assert [row["epoch_s"] for row in stream] == [1.0, 0.5]
    assert stream[1]["heads"] > stream[0]["heads"] >= 1
    assert stream[0]["leaves_bytes"] == 32 * 198
    assert stream[0]["seal"]["wall_s"] > 0
