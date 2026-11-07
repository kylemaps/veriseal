# Measuring veriseal on a robot

`measure.py` measures what sealing a log costs on the computer it runs on. Run it on the robot's
own computer, with logs the robot recorded, and send back the results file.

## What it measures

For each log, a few times over, it runs the real `veriseal seal` (offline, no timestamp
submission) and `veriseal verify`, each as its own process, and records the wall-clock time, the
CPU time and the peak memory of each run. If the computer has a power sensor, it also records the
extra energy sealing takes: average power while sealing minus average power while idle, times
the sealing time.

It finds a power sensor by itself, in this order:

| Sensor | Computers | Notes |
|---|---|---|
| `tegrastats` | NVIDIA Jetson | Board input power (`VDD_IN`, or `POM_5V_IN` on the Nano) |
| INA3221 (`/sys/bus/i2c/drivers/ina3221`) | NVIDIA Jetson | Same sensor, read directly |
| `vcgencmd pmic_read_adc` | Raspberry Pi 5 | SoC and memory rails only, not USB devices |
| Intel RAPL (`/sys/class/powercap`) | Intel PCs, NUCs | CPU package only; usually needs `sudo` |
| Battery (`/sys/class/power_supply/BAT*`) | Laptops | Only while running on battery |

Without a sensor it still records time and memory, which is enough to estimate energy later.

## Running it

It needs Python 3.11 or newer and about five minutes. On Ubuntu 22.04 (ROS 2 Humble), whose
Python is 3.10, [uv](https://docs.astral.sh/uv/) can provide a newer one without touching
the system:

```bash
git clone https://github.com/kylemaps/veriseal && cd veriseal
uv venv --python 3.12 && source .venv/bin/activate     # or: python3 -m venv .venv
uv pip install ".[ros1]"                               # or: pip install ".[ros1]"
python bench/measure.py /path/to/log.mcap /path/to/other.bag --runs 5 --battery-wh 720
```

- Give `.mcap` files, ROS 1 `.bag` files, or ROS 2 bag folders recorded with `--storage mcap`.
- `--battery-wh` is your robot's battery capacity (720 is a Husarion Panther's standard battery,
  so change it to match yours); with it, the results also give sealing's share of the battery per
  hour of recording.
- On an Intel computer such as a NUC, the energy counter is readable only by root. Run the
  script with the environment's own Python, `sudo .venv/bin/python bench/measure.py ...`,
  because a plain `sudo python` skips the environment.
- Leave the robot otherwise idle while it runs: the first 10 seconds measure idle power.
- On a Jetson, note the power mode (`sudo nvpmodel -q`); the script records it when it can.

It writes `veriseal-measurements.json`. The file holds timings, file sizes, message counts and
a description of the computer (model, CPU, memory, OS), but nothing from inside the logs. The
logs are only read; seals go to a temporary folder that is deleted afterwards.
