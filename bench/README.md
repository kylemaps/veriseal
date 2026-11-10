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

## The streaming prototype

More scripts cover the checkpoint design. None needs a robot.

`bench/window.py` works out how much of a log a hacked robot could still change or remove, for each export interval. To measure a real link, start a witness on another machine, then run the script in real time against it:

```bash
python -m veriseal.witness --store witness.jsonl --host 0.0.0.0 --port 8787
python bench/window.py --url http://WITNESS:8787 --witness-pub witness.pub.pem --live \
    --task 600 --epoch 1 --export 1,10,60 --out window.json
```

The witness prints its public key when it starts: save that as `witness.pub.pem`. It has no login, so keep it on a private network.

A sealer that follows the recorder's file signs each head a little after its epoch ends. `--head-delay SECONDS` adds that delay to every window; take it from `head_delay` in the `stats.json` that `python -m veriseal.tail seal` writes. `bench/plot_window.py` draws one or more results as an SVG chart, with no extra packages:

```bash
python bench/plot_window.py window-wifi.json window-lte.json --out window.svg
```

`bench/attacks.py` runs each attack against each design with the real verifiers, and prints any result that differs from the expected one:

```bash
python bench/attacks.py --log task.mcap --out attacks.json
```

`bench/memory_dump.py` checks whether erased epoch keys are still in the recorder's memory. A child process closes 20 epochs, then the script reads the child's memory and counts the erased seeds and private keys it can still find. It runs on Linux (the NUC and the Pi) and Windows, needs no `sudo`, and reads nothing from any log:

```bash
python bench/memory_dump.py --runs 10 --out memory.json
```

`bench/tail_dry_run.py` tests the sealer that reads the recorder's file as it grows (`python -m veriseal.tail`). The script plays the recorder: it writes a recorded task into a new MCAP file in real time while the sealer runs, then verifies the file and reports how far behind the recorder the sealer ran. `--chunk-kib 0` writes the file without chunks:

```bash
python bench/tail_dry_run.py task.bag --chunk-kib 768 --out tail-768k.json
python bench/tail_dry_run.py task.bag --chunk-kib 0 --out tail-nochunk.json
```

`bench/ros2_replay/` runs the same test through the real ROS 2 recorder, in Docker, so it needs no robot either. Convert the task to a ROS 2 bag first (`--dst-version 5` suits Humble; add `--exclude-msgtype` for any message type that only exists in ROS 1), build the image, then run one replay per recorder setting. The arguments after the name are the grace period in seconds and any options for `ros2 bag record`:

```bash
rosbags-convert --src task.bag --dst work/ros2bag --dst-storage mcap --dst-version 5
docker build -t veriseal-ros2-humble bench/ros2_replay
docker run --rm -v "$PWD:/src:ro" -v "$PWD/work:/work" veriseal-ros2-humble \
    bash /src/bench/ros2_replay/replay.sh fastwrite 6 --storage-preset-profile fastwrite
```

Each run leaves `work/runs/NAME/report.json`: the messages played, recorded and sealed, the verify result, the recorder's chunks, and how far behind the sealer ran. `NOSEAL=1` records without the sealer, as a baseline for dropped messages, and `CONVERT=1` also checks the seal after `ros2 bag convert`.

## On the robot: the live replay

`bench/live_replay.py` is the same test on a computer with ROS 2 installed, the NUC in our case, and it measures energy as well. It replays a recorded task (a ROS 2 bag folder of MCAP files) through the real recorder in three setups that take turns: recording alone (A), recording and sealing (B), and recording, sealing and sending each head to a witness (C). Every run is measured over the same fixed time, so the differences in energy between setups are what sealing and sending cost:

```bash
source /opt/ros/humble/setup.bash
sudo chmod a+r /sys/class/powercap/intel-rapl:0/energy_uj   # once per boot, for the energy counter
python bench/live_replay.py TASK_BAG --out live.json \
    --witness http://WITNESS:8787 --witness-pub witness.pub.pem
```

The default is 25 rounds of all three setups, about 1 h 50 min for a 65 s task. Each run also reports the messages the recorder dropped, how far behind the recorder the sealer ran, whether the result verifies, and how long each head took to reach the witness. Recordings are deleted after each run.
