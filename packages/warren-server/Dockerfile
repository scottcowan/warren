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

# session-manager-plugin: ECSRuntime.exec_stream runs `aws ecs execute-command`-style
# sessions through it. Pinned version, each arch's .deb verified against its sha256
# before it reaches the final image.
FROM python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce AS session-manager-plugin
ARG TARGETARCH
ARG SESSION_MANAGER_PLUGIN_VERSION=1.2.896.0
ARG SESSION_MANAGER_PLUGIN_SHA256_AMD64=53f51fcc67314a4bf85888a38a3967cd41f8d0f28a60a9469a63acf935ba713e
ARG SESSION_MANAGER_PLUGIN_SHA256_ARM64=914eeca87b18b55356c58be197080f73742b3ca60d3823f0a45670dc9056aa9c
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) dir=ubuntu_64bit; sha="$SESSION_MANAGER_PLUGIN_SHA256_AMD64" ;; \
      arm64) dir=ubuntu_arm64; sha="$SESSION_MANAGER_PLUGIN_SHA256_ARM64" ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    python -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], "/session-manager-plugin.deb")' \
      "https://s3.amazonaws.com/session-manager-downloads/plugin/${SESSION_MANAGER_PLUGIN_VERSION}/${dir}/session-manager-plugin.deb"; \
    echo "$sha  /session-manager-plugin.deb" | sha256sum -c -

FROM python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce
# 3.11-slim as of 2026-10-17
# No `podman` CLI: workspace networks are managed through the API socket
# (podman-py), and the per-workspace egress read (`find_host_veth`/
# `read_egress_bytes`, which need `podman unshare --rootless-netns`) can't run
# inside this container at all (node2 finding, 2026-09-19): a rootless container can never
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
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client \
    && rm -rf /var/lib/apt/lists/*
RUN --mount=type=bind,from=session-manager-plugin,source=/session-manager-plugin.deb,target=/tmp/session-manager-plugin.deb \
    dpkg -i /tmp/session-manager-plugin.deb && session-manager-plugin --version
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
RUN useradd -u 1000 -m warren
USER warren
WORKDIR /var/lib/warren
VOLUME /var/lib/warren
# Listens on 127.0.0.1 by default (ECS reaches it via SSM port-forward to the task's
# loopback). Publishing with `-p` needs WARREN_HOST=0.0.0.0 plus TLS or
# WARREN_ALLOW_INSECURE_HTTP=1 -- see the package README's "Listening address".
EXPOSE 8420
CMD ["python", "-m", "warren"]
