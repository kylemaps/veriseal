# Runbook for the robot measurements

These runs measure what sealing costs on a real robot. Each step says where it runs, how long it
takes and what file it leaves. Every results file goes in one folder, which is packed up at the
end. None of the files hold anything from inside the logs: only counts, times, energy, sizes and a
description of each computer.

**Safety first.** Step 4 replays a recorded task, motion commands included. The script keeps the
replay on its own ROS domain, on the NUC only, so it can't reach the robot's nodes. Keep the
motors off during that step all the same.

## At a glance

| Step | Where | Time | Leaves |
|---|---|---|---|
| 1. Set up | NUC, Pi, one lab PC | 15 min each | |
| 2. Facts about the robot | NUC, Pi | 5 min | `facts.txt` |
| 3. Start the witness | lab PC | 5 min, then leave it running | `witness.pub.pem` |
| 4. Live replay with energy | NUC | 2 h, unattended | `live-fastwrite.json`, `live-default.json` |
| 5. Memory test | NUC, Pi | 5 min each | `memory-nuc.json`, `memory-pi.json` |
| 6. What sealing a finished log costs | NUC, Pi | 1 h each | `nuc-seal.json`, `pi-seal.json` |
| 7. Checkpoints over the real network | NUC | 30 min per link | `window-wifi.json`, `deliveries-wifi.jsonl` |
| 8. The attack table on a real log | any | 10 min | `attacks.json` |
| 9. What the whole robot draws | NUC | 40 min | three battery recordings |

If time runs short, steps 4, 5 and 7 matter most.

## 1. Set up (15 minutes, once per computer)

ROS 2 Humble comes with Python 3.10, and veriseal needs 3.11 or newer. `uv` installs a separate
Python for veriseal without touching the system one:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh     # then open a new terminal
git clone https://github.com/kylemaps/veriseal.git
cd veriseal
git checkout feat/streaming-seal
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e ".[ros1]"
mkdir -p ~/veriseal-results
```

Check it worked: `.venv/bin/python -m veriseal.tail --help` prints a usage line. Every command
below runs from the `veriseal` folder and calls `.venv/bin/python` directly, so there is nothing
to activate. Steps that use ROS say so: source it first in that terminal. The commands below say
`humble`; if the robot runs another ROS 2 release, such as Jazzy, use its name instead.

This step needs the internet once, for `uv`, Python 3.12 and the packages. Nothing after it
does, apart from reaching the witness on the lab network.

## 2. Facts about the robot (5 minutes, once per computer)

Copy the output into `~/veriseal-results/facts.txt`, and add by hand the battery size in Wh and
how the robot reaches the network (Wi-Fi, LTE or both).

```bash
source /opt/ros/humble/setup.bash
cat /sys/class/dmi/id/product_name             # NUC model
lscpu | grep "Model name"
cat /proc/device-tree/model                    # on the Pi
ls /dev/tpm0 /dev/tpmrm0                       # is there a TPM?
echo $ROS_DISTRO
ros2 pkg list | grep rosbag2_storage_mcap      # can the recorder write MCAP?
ls /sys/class/powercap/intel-rapl:0/energy_uj  # the NUC's energy counter
ros2 topic list | grep -i battery              # the battery topic's name
```

If `rosbag2_storage_mcap` is missing: `sudo apt install ros-$ROS_DISTRO-rosbag2-storage-mcap`.

## 3. Start the witness (5 minutes on a lab PC, then leave it running)

The witness stands in for the outside party that checks the robot's work: it keeps each checkpoint the robot sends and signs
a receipt for it. Run it on a lab PC that is not on the robot, set up as in step 1:

```bash
.venv/bin/veriseal keygen --out witness.key.pem --pub witness.pub.pem
.venv/bin/python -m veriseal.witness --key witness.key.pem --store ~/witness.jsonl \
    --host 0.0.0.0 --port 8787
```

Copy `witness.pub.pem` into the `veriseal` folder on the NUC. Check the NUC can reach the
witness: `curl http://LAB-PC:8787/heads/test` should print `[]`. In the commands below, replace
`LAB-PC` with that computer's name or address. The witness has no login, so keep it on the lab
network.

## 4. Live replay with energy (2 hours, unattended, on the NUC)

This is the main measurement: what recording, sealing and sending cost while the recorder runs.
`bench/live_replay.py` plays a recorded task into the real recorder in three setups that take
turns, and measures each over the same fixed time:

- A: recording only
- B: recording, with the sealer reading the file as it grows
- C: as B, with every checkpoint sent to the witness

You need one recorded task of about a minute, as a ROS 2 bag folder in MCAP format, recorded on
the robot so that all its message types are installed. If the bag is in the default SQLite format
(a `.db3` file), convert it first:

```bash
printf 'output_bags:\n- uri: task_mcap\n  storage_id: mcap\n  all: true\n' > to-mcap.yaml
ros2 bag convert -i TASK_DB3_FOLDER -o to-mcap.yaml
```

If the only recording of a task is a ROS 1 `.bag` file, convert that instead. `rosbags-convert`
was installed with veriseal in step 1:

```bash
.venv/bin/rosbags-convert --src task.bag --dst task_mcap --dst-storage mcap --dst-version 5
```

Message types that exist only in ROS 1 (actions, `move_base`) can't be played in ROS 2. If the
conversion stops on one, leave it out with `--exclude-msgtype TYPE` and run it again. The live
replay names any topic whose message package is missing on the NUC ("never recorded"). Install
the package, for example `sudo apt install ros-humble-control-msgs`, or carry on with the
shorter topic list and note it in `facts.txt`.

Before starting: motors off, nothing else heavy running, and the same power state for the whole
run (on the charger or on battery; note which in `facts.txt`). Then, with `TASK_BAG` replaced by
the task's bag folder:

```bash
source /opt/ros/humble/setup.bash
sudo chmod a+r /sys/class/powercap/intel-rapl:0/energy_uj   # once per boot, for the energy counter
.venv/bin/python bench/live_replay.py TASK_BAG --out ~/veriseal-results/live-fastwrite.json \
    --witness http://LAB-PC:8787 --witness-pub witness.pub.pem
```

The first line it prints is the plan. If it ends with "Energy from: nothing found", stop it with
Ctrl-C and run the `chmod` line again. After that it prints one line per run. Results are saved
after every run, so stopping early keeps what is done. Every B and C line should end with
"verified".

The run above uses the recommended recorder setting, the fastwrite profile, which writes without
chunks. Then run a
shorter one with the recorder's default settings, which write the file in chunks, to measure how
much the chunks delay the sealer (15 minutes):

```bash
.venv/bin/python bench/live_replay.py TASK_BAG --record-args "" --setups A,B --repeats 5 \
    --out ~/veriseal-results/live-default.json
```

## 5. Memory test (5 minutes per computer, on the NUC and the Pi)

Checks whether the throw-away keys are really gone from memory once used. No `sudo` needed.

```bash
.venv/bin/python bench/memory_dump.py --runs 10 --out ~/veriseal-results/memory-nuc.json
```

On the Pi, name the file `memory-pi.json`. Each line reports how many erased keys the scan still
found; whatever the numbers, they are the result.

## 6. What sealing a finished log costs (about 1 hour per computer, on the NUC and the Pi)

Use recordings of 1, 10 and 60 minutes, plus the one with camera and lidar. The script reads
MCAP files, ROS 2 bag folders and ROS 1 `.bag` files. Leave the robot
otherwise idle. On the NUC, the `chmod` line from step 4 lets the script read the energy counter.

```bash
.venv/bin/python bench/measure.py task-1min.mcap task-10min.mcap task-60min.mcap \
    task-camera.mcap --runs 5 --battery-wh 720 --stream 60,10,1 \
    --out ~/veriseal-results/nuc-seal.json
```

Change `720` if the battery is the 1440 Wh one, and name the file `pi-seal.json` on the Pi.
`--stream 60,10,1` also seals each log as if it were being recorded, with a checkpoint every 60,
10 and 1 seconds.

## 7. Checkpoints over the real network (about 30 minutes per link, on the NUC)

With the witness from step 3 running, run this once over Wi-Fi and once over LTE, if the robot
has both. Name the files for the link.

```bash
.venv/bin/python bench/window.py --url http://LAB-PC:8787 --witness-pub witness.pub.pem --live \
    --task 600 --epoch 1 --export 1,10,60 \
    --deliveries ~/veriseal-results/deliveries-wifi.jsonl --out ~/veriseal-results/window-wifi.json
```

If the link drops during a run, leave it running: a dropped link is part of the measurement.
Write down roughly when it happened.

## 8. The attack table on a real log (about 10 minutes, any computer)

```bash
.venv/bin/python bench/attacks.py --log task-1min.mcap --out ~/veriseal-results/attacks.json
```

It ends with a line that says `findings: none`, or lists any result that differs from the expected
one. Keep the file either way.

## 9. What the whole robot draws (about 40 minutes, on the NUC)

This needs only the battery topic from step 2. Record that topic alone for 10 minutes in each of
three states, one after another, without moving the robot:

| File | What the robot is doing |
|---|---|
| `power-idle` | Nothing beyond being switched on |
| `power-recording` | Recording the task's usual topics with `ros2 bag record` |
| `power-sealing` | Recording the usual topics, with the sealer running on that recording |

In each state, record the battery topic in one terminal, with the state's name:

```bash
source /opt/ros/humble/setup.bash
ros2 bag record -s mcap -o ~/veriseal-results/power-idle /BATTERY_TOPIC
```

For `power-recording`, record the usual topics in a second terminal at the same time. That
recording goes to `/tmp`, so nothing from it ends up in the results:

```bash
ros2 bag record -s mcap --storage-preset-profile fastwrite -o /tmp/usual-a USUAL_TOPICS
```

For `power-sealing`, do the same with a new folder name (`/tmp/usual-b`), and start the sealer
on it in a third terminal:

```bash
.venv/bin/python -m veriseal.tail seal /tmp/usual-b/usual-b_0.mcap --out-dir /tmp/usual-b-sealed
```

## Packing the results

```bash
tar czf ~/veriseal-results.tar.gz -C ~ veriseal-results
```

`veriseal-results.tar.gz` holds everything the analysis needs.

## If something goes wrong

- `ros2: command not found`: source ROS in that terminal.
- `No module named veriseal`: run from the `veriseal` folder with `.venv/bin/python`.
- "Energy from: nothing found" on the NUC: run the `chmod` line from step 4; it resets at
  every boot.
- The sealer warns that messages "reached the sealer after their epoch had closed": the
  recorder is writing in chunks. That is expected in `live-default.json`, not in the fastwrite run.
- A verify line says "a message was sealed too long after its time": the recorder paused for
  longer than the sealer waits (6 s by default), so some messages were signed late. The run is
  still useful and the count is data. Keep the file as it is.
- Setup C shows lost sends: check the witness is running and that `curl` from step 3 still works
  (port 8787 open). The run carries on either way, and the lost sends are data.
- A run stops part-way: its results file keeps every finished run, so it is still usable.
- `live_replay.py` refuses to start because "the recorder can't write MCAP here": install the
  plugin as in step 2.
- A live replay line says some topics were "never recorded": their message types are not
  installed on that computer, so the player skipped them. Install the robot's message packages,
  or use a bag recorded on that same computer.
- A live replay line says "NOTHING recorded": the recorder failed to start. Its error is in
  `processes.log`, in that run's folder under `live-replay-work/`.
