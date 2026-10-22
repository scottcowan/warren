# syntax=docker/dockerfile:1.7
# Multi-stage uv-based build (Plan 01-05, RESEARCH Pattern 7, D-16).
# Final image runs as non-root UID 1000 warren user.
#
# warren-common is now a local workspace dependency (packages/warren-common),
# not a git+https one — this build needs the whole monorepo as its context
# (`docker build -f packages/warren-server/Dockerfile .` from the repo root),
# not just this directory, so uv can see the workspace root pyproject.toml/
# uv.lock and resolve the local path source. That also means the old two-
# stage lock-then-sync layer-caching split (bind-mount just pyproject.toml,
# lock, then copy everything) no longer applies cleanly — a single `COPY .`
# + `uv sync --package` trades some layer-cache granularity for correctness.

FROM python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce AS builder
# 3.11-slim as of 2026-10-17
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:latest@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 /uv /uvx /bin/
# uv:latest as of 2026-10-17
ENV UV_PYTHON_DOWNLOADS=0 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
WORKDIR /app

COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --package warren-server --locked --no-editable --no-dev

FROM python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce
# 3.11-slim as of 2026-10-17
# `podman` CLI is still needed here for exactly one thing: ensure_bridge_network's
# `podman network create`/`network exists` (network/egress.py). That does NOT hit
# the "remote client" restriction (only `podman unshare` does), so CONTAINER_HOST
# + any reasonably recent podman package is fine for it — no version pinning, no
# runc/uidmap, no local-mode bind mounts needed for this one call.
#
# The actual per-workspace egress read (`find_host_veth`/`read_egress_bytes`,
# which DO need `podman unshare --rootless-netns`) no longer runs inside this
# container at all (node2 finding, 2026-09-19): a rootless container can never
# genuinely own the kernel-level subuid range `podman unshare` needs to build a
# second nested namespace layer, no matter what's bind-mounted in or what
# capabilities are added — confirmed via `newuidmap: write to uid_map failed:
# Operation not permitted` even with --userns=host/keep-id and SETUID/SETGID
# capabilities added. That work now runs in a small native shim on node2 itself
# (scripts/egress_shim.py, run by the real host user under systemd), reached over
# WARREN_EGRESS_SHIM_SOCKET — see docs/warren-server-deploy.md.
# git + openssh-client: warren.git.manager.GitManager shells out to a real `git`
# binary (GitPython) for every server-side worktree clone/pull (LIFE-03), and an
# SSH-remote clone additionally needs `ssh` on PATH for GIT_SSH_COMMAND to exec
# (warren/git/manager.py's _ssh_key_env). Neither was ever installed here --
# every clone, HTTPS/GitHub-App or SSH, has silently had nothing to actually
# shell out to on a real deployment until now.
RUN apt-get update && apt-get install -y --no-install-recommends podman git openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
ENV CONTAINER_HOST="unix:///run/user/1000/podman/podman.sock"
RUN useradd -u 1000 -m warren
USER warren
WORKDIR /var/lib/warren
VOLUME /var/lib/warren
EXPOSE 8420
CMD ["python", "-m", "warren"]
