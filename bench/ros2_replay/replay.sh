#!/bin/bash
# One live replay: a recorded task through the real ROS 2 recorder, sealed while it is written.
#
#   bash /src/bench/ros2_replay/replay.sh NAME GRACE_SECONDS [extra "ros2 bag record" options]
#
# Runs inside the image built from this folder, with the repository at /src and a work folder
# at /work that holds the task as a ROS 2 bag in /work/ros2bag. The recording stays on the
# container's own disk, since a folder shared with the host adds delays a robot doesn't have;
# the report and logs go to /work/runs/NAME.
#
# NOSEAL=1 records without the sealer, as a baseline for dropped messages. CONVERT=1 also
# rewrites the recording with "ros2 bag convert" and checks it against the same seal.
set -m
source "/opt/ros/$ROS_DISTRO/setup.bash"
set -u
NAME=$1; GRACE=$2; shift 2
OUT=/tmp/runs/$NAME
rm -rf "$OUT"; mkdir -p "$OUT"
TOPICS=$(python3 -c "import yaml; m = yaml.safe_load(open('/work/ros2bag/metadata.yaml'))['rosbag2_bagfile_information']; print(' '.join(t['topic_metadata']['name'] for t in m['topics_with_message_count']))")
SEALER=""
if [ "${NOSEAL:-0}" != 1 ]; then
    /opt/vs/bin/python -m veriseal.tail seal "$OUT/rec/rec_0.mcap" --out-dir "$OUT/sealed" \
        --grace-seconds "$GRACE" --max-seconds 900 > "$OUT/sealer.log" 2>&1 &
    SEALER=$!
fi
ros2 bag record -s mcap -o "$OUT/rec" "$@" $TOPICS > "$OUT/recorder.log" 2>&1 &
RECORDER=$!
sleep 2
ros2 bag play -s mcap /work/ros2bag --delay 3 > "$OUT/player.log" 2>&1
sleep 2
kill -INT $RECORDER; wait $RECORDER
if [ -n "$SEALER" ]; then
    for i in $(seq 1 120); do kill -0 $SEALER 2>/dev/null || break; sleep 1; done
    kill -INT $SEALER 2>/dev/null; wait $SEALER
    /opt/vs/bin/python -m veriseal.tail verify "$OUT/rec/rec_0.mcap" --out-dir "$OUT/sealed" \
        > "$OUT/verify.log" 2>&1
fi
if [ "${CONVERT:-0}" = 1 ] && [ -n "$SEALER" ]; then
    printf 'output_bags:\n- uri: %s\n  storage_id: mcap\n  storage_preset_profile: zstd_small\n  all: true\n' \
        "$OUT/converted" > "$OUT/convert.yaml"
    ros2 bag convert -i "$OUT/rec" -o "$OUT/convert.yaml" > "$OUT/convert.log" 2>&1
    /opt/vs/bin/python -m veriseal.tail verify "$OUT/converted/converted_0.mcap" \
        --out-dir "$OUT/sealed" > "$OUT/convert-verify.log" 2>&1
fi
/opt/vs/bin/python /src/bench/ros2_replay/report.py "$OUT" "$NAME" "$GRACE" "$*"
mkdir -p "/work/runs/$NAME"
cp "$OUT"/*.log "$OUT"/report.json "/work/runs/$NAME/" 2>/dev/null
cp "$OUT"/sealed/stats.json "/work/runs/$NAME/" 2>/dev/null
exit 0
