# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Hardened multi-stage image for DetRisk (Phase 3).
#
# Hardening choices (the interview talking points):
#   * Multi-stage: build tooling + caches live in the builder and never ship.
#   * Base image PINNED BY DIGEST, not a mutable tag — same supply-chain
#     principle as SHA-pinning GitHub Actions.
#   * Dependencies installed into an isolated venv that is copied wholesale
#     into a clean runtime stage (no pip/compilers in the final image).
#   * Runs as a NON-ROOT user (uid 1001); filesystem is owned read-only and
#     the app needs no write access at runtime.
#   * No package manager invoked in the final stage; minimal surface.
#
# Runtime layout note: risk_chat.py loads its sibling risk_engine.py via a
# RELATIVE path and searches ../../policy for config, so the process MUST run
# with CWD = /app/src/utils. WORKDIR is set accordingly (documented, not magic).
# ---------------------------------------------------------------------------

# --- Builder stage ---------------------------------------------------------
FROM python:3.11-slim@sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0 AS builder

# Fail fast, no .pyc, no pip version chatter, unbuffered logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build-only OS packages (compilers for any C-extension wheels). These stay in
# the builder and are discarded — they never reach the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Isolated virtualenv we will copy into the runtime stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies first (better layer caching), then the app.
#
# sentence-transformers pulls in PyTorch, which by default bundles ~4.5GB of
# NVIDIA CUDA/GPU libraries (nvidia-*, triton). DetRisk does CPU-only inference,
# so we install the CPU-only torch build from PyTorch's dedicated index BEFORE
# the rest — pip then sees the requirement satisfied and skips the GPU stack.
# This is a deliberate attack-surface + image-size reduction (~5.5GB -> ~1.5GB).
COPY requirements.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r requirements.txt

# --- Runtime stage ---------------------------------------------------------
FROM python:3.11-slim@sha256:a3ab0b966bc4e91546a033e22093cb840908979487a9fc0e6e38295747e49ac0 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Create an unprivileged user/group; the app never needs root.
RUN groupadd --gid 1001 detrisk \
    && useradd --uid 1001 --gid 1001 --no-create-home --shell /usr/sbin/nologin detrisk

# Copy the prebuilt venv from the builder (no pip/compilers in this stage).
COPY --from=builder /opt/venv /opt/venv

# Copy only what the app needs at runtime (see .dockerignore for exclusions).
WORKDIR /app
COPY --chown=root:root src/ ./src/
COPY --chown=root:root policy/ ./policy/

# Drop privileges. Files are owned by root and world-readable, so the non-root
# process can read but not modify them (defense in depth).
USER 1001

# risk_chat.py resolves risk_engine.py and ../../policy relative to CWD.
WORKDIR /app/src/utils

# Documents the contract: interactive risk-assessment CLI.
ENTRYPOINT ["python", "risk_chat.py"]
