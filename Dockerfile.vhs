FROM ghcr.io/charmbracelet/vhs

# Add Python 3 (Debian Trixie-based image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Create a venv so pip installs don't conflict with Debian's system Python
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install veriseal and all Python deps
# --prefer-binary avoids compiling cryptography from source (manylinux wheels exist)
WORKDIR /build
COPY pyproject.toml LICENSE README.md ./
COPY src/ ./src/
# The wheel force-includes web/verify.html (pyproject [tool.hatch...force-include]),
# so the build context must contain it or `pip install .` fails.
COPY web/ ./web/
RUN pip install --no-cache-dir --prefer-binary .

WORKDIR /vhs
