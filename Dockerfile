# syntax=docker/dockerfile:1.7
# --------------------------------------------------------------------------- #
# Stage 1 – build a wheel in an isolated environment
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Only what the build needs, so this layer stays cached.
COPY pyproject.toml README.md LICENSE ./
COPY core ./core
COPY cli ./cli
COPY reporters ./reporters
COPY data ./data
COPY main.py ./

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
 && /opt/venv/bin/pip install . \
 && /opt/venv/bin/pip uninstall -y pip setuptools wheel \
 && find /opt/venv -name '__pycache__' -type d -prune -exec rm -rf {} + \
 && find /opt/venv -name '*.pyc' -delete

# --------------------------------------------------------------------------- #
# Stage 2 – minimal runtime
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="asynscan" \
      org.opencontainers.image.description="Asynchronous port scanner, banner grabber and TLS inspector" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/laithfarhat-cell/Asynchronous-Port-Scanner-Banner-Grabber-"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN groupadd --gid 10001 scanner \
 && useradd --uid 10001 --gid scanner --create-home --shell /usr/sbin/nologin scanner \
 && mkdir -p /work && chown scanner:scanner /work

# Signature database + port presets (also usable via --signatures).
COPY --from=builder /build/data /usr/local/share/asynscan
ENV ASYNSCAN_DATA_DIR=/usr/local/share/asynscan

COPY --from=builder /opt/venv /opt/venv

WORKDIR /work
USER scanner

# Interactive TTY by default; override the CMD to pass your own flags, e.g.
#   docker run --rm asynscan -t 10.0.0.0/24 --top-ports 100 -oH /work/report.html
ENTRYPOINT ["asynscan"]
CMD ["--help"]

# Reports are written here; mount a host directory to keep them.
VOLUME ["/work"]
