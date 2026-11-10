# syntax=docker/dockerfile:1.7
# warren-docker-base — multi-arch base image with system tools + warren-sidecar.
# The workload runs as `warren` (uid 1000), not root, whenever the bind mounts are owned
# by uid 1000 (podman keep-id, the default); it stays root over root-owned or other-uid
# mounts (podman `host` userns, rootful docker). See entrypoint.py and the server README.
# Build from repo root (context=.): docker build -f images/warren-docker-base/Dockerfile .
# Extension images (e.g. warren-base-claude-code) FROM this image via ARG BASE_IMAGE.

# 3.11-slim as of 2026-10-17 (a trailing comment on the FROM line itself is invalid
# Dockerfile syntax -- "FROM requires either one or three arguments" -- audit S1)
#
# BASE_REGISTRY only picks WHERE the digest-pinned base is fetched from; the digest itself
# fixes WHAT is built. CI may pass mirror.gcr.io/library (verified to serve this identical
# index digest by .github/scripts/resolve-base-registry.sh) to avoid Docker Hub's anonymous
# pull rate limit on shared runner IPs. Default is the original Docker Hub source.
ARG BASE_REGISTRY=docker.io/library
FROM ${BASE_REGISTRY}/python:3.11-slim@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce

# System tools required inside workspace containers
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ssh-client \
        jq \
        curl \
        tmux \
        zsh \
    && rm -rf /var/lib/apt/lists/*

# The workload user. The entrypoint starts as container root, does what needs root, then
# drops to this user (uid/gid 1000, the ECS images' `warren` and the one
# warren-docker-ssh-base logs SSH sessions in as) for the tmux session, harnesses, agent
# supervisor and app. The image deliberately sets no USER: sshd (docker-ssh-base) needs
# root at start, and the drop depends on who owns the bind mounts (entrypoint.py).
# /workspace and /var/lib/warren are where a workspace with no bind mount writes.
RUN groupadd -g 1000 warren \
    && useradd -u 1000 -g warren -m -d /home/warren -s /bin/bash warren \
    && mkdir -p /workspace /var/lib/warren \
    && chown 1000:1000 /workspace /var/lib/warren
# Read by warren-server (runtime/podman.py): this image's workload runs as uid 1000 over
# keep-id mounts, so `warren exec` sessions there run as uid 1000 too.
LABEL dev.warren.workload-uid="1000"
# A root `podman exec ... tmux` reaches the workload's tmux server as the workload user.
COPY --chmod=0755 images/warren-docker-base/warren-tmux.sh /usr/local/bin/tmux

# UX-1: warren's own prompt/banner, shared with the locally-written workspace
# .zshrc (packages/warren-cli/src/warren_cli/dispatch.py's
# _warren_banner_zsh_text) -- same file, so there's one definition of this
# content instead of two that can drift. System-wide (/etc/zsh/zshrc) so it
# applies regardless of $HOME; it reads WARREN_PROJECT/WARREN_TEMPLATE/
# WARREN_WORKSPACE_ID from the environment at shell-start time (set by
# PodmanRuntime/DockerRuntime.provision()), so this one image file works
# unmodified for every workspace that runs it.
COPY packages/warren-common/src/warren_common/assets/warren_banner.zsh /etc/zsh/zshrc
# AG2a: the template's harnesses as warren shell commands, plus `warren resume`, for zsh
# and bash. Generated from the harness profiles (warren_common.harness_shell).
COPY packages/warren-common/src/warren_common/assets/warren_harness.sh /etc/warren/harness.sh
COPY packages/warren-common/src/warren_common/assets/warren_banner.bash /etc/warren/banner.bash
COPY --chmod=0755 packages/warren-common/src/warren_common/assets/warren_harness_init.sh /usr/local/bin/warren-harness-init
# AG5: the state hook the harness hook configs call (root-owned, read-only to the workspace).
COPY --chmod=0755 packages/warren-common/src/warren_common/assets/warren_state_hook.sh /usr/local/bin/warren-state-hook
# AG2b: supervises a `kind: agent` workspace's harness next to the shell.
COPY --chmod=0755 packages/warren-common/src/warren_common/agent_supervisor.py /usr/local/bin/warren-agent-supervisor
# git_write templates: the podman runtime writes repo-scoped GitHub tokens to
# /run/warren-git/<owner>; this helper hands them to git for https://github.com only.
COPY --chmod=0755 packages/warren-common/src/warren_common/assets/warren_git_credential.sh /usr/local/bin/git-credential-warren
RUN git config --system credential.https://github.com.helper /usr/local/bin/git-credential-warren \
    && git config --system credential.https://github.com.useHttpPath true
RUN printf '\n[ -r /etc/warren/harness.sh ] && . /etc/warren/harness.sh\n' >> /etc/zsh/zshrc \
    && printf '\n[ -r /etc/warren/banner.bash ] && . /etc/warren/banner.bash\n[ -r /etc/warren/harness.sh ] && . /etc/warren/harness.sh\n' >> /etc/bash.bashrc

# uv — fast Python package manager; copied from official uv image
COPY --from=ghcr.io/astral-sh/uv:latest@sha256:4a1f3666816dafadd20ceb71eac9a7d56d7ef30279f7d64048519ab901ada336 /uv /uvx /bin/
# uv:latest as of 2026-10-17

# Install warren-sidecar from monorepo source using repo-root build context (Pitfall 7).
# The bind-mount makes the full repo available at /repo without adding it to the image layer.
RUN --mount=type=bind,source=.,target=/repo \
    --mount=type=cache,target=/root/.cache/uv \
    uv pip install --system /repo/packages/warren-sidecar

# Workspace entrypoint: emits NDJSON preflight events then supervises workspace app
COPY images/warren-docker-base/entrypoint.py /entrypoint.py
RUN chmod +x /entrypoint.py

WORKDIR /workspace

# Absolute interpreter path, not bare "python" -- an extension image (e.g.
# warren-docker-dev-base) that installs its own version manager (pyenv, nvm)
# prepends its shims ahead of /usr/local/bin on PATH, which would otherwise
# silently redirect this ENTRYPOINT to a bare interpreter with none of
# warren-sidecar's dependencies installed (structlog, warren_sidecar
# itself) -- a real failure this image shipped with (sidecar_import_error:
# "No module named 'structlog'" under warren-docker-dev-base, fixed 2026-10-13).
# This process is warren's own infra, not the user's dev shell, so it must
# never be subject to a downstream layer's PATH customization.
ENTRYPOINT ["/usr/local/bin/python3.11", "/entrypoint.py"]
# No CMD — set by extension images (e.g. CMD ["claude"] in warren-base-claude-code)
