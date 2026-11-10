# ROS 2 with the MCAP recorder plugin, plus Python 3.12 for veriseal (Humble ships 3.10).
# Mount the repository at /src; veriseal runs from there without being installed.
#   docker build -t veriseal-ros2-humble bench/ros2_replay
#   docker build --build-arg ROS_DISTRO=jazzy -t veriseal-ros2-jazzy bench/ros2_replay
ARG ROS_DISTRO=humble
FROM ros:${ROS_DISTRO}-ros-base
ARG ROS_DISTRO
RUN apt-get update && apt-get install -y --no-install-recommends \
        ros-${ROS_DISTRO}-rosbag2-storage-mcap ros-${ROS_DISTRO}-control-msgs \
        curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"
RUN uv venv /opt/vs --python 3.12 && \
    uv pip install --python /opt/vs/bin/python "mcap>=1.1.1,<2" cryptography rosbags zstandard lz4
ENV PYTHONPATH=/src/src
