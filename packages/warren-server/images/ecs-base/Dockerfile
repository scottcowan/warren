# syntax=docker/dockerfile:1.7
# ecs-base — minimal workspace image for ECS-backed workspaces (D-10 sibling to
# ../workspace-base, which targets Docker instead — see that Containerfile's own header).
# Published as ghcr.io/scottcowan/warren-ecs-base.
#
# Debian bookworm-slim (glibc) since 2.0.0; 1.x was Alpine (musl). Prebuilt PyPI
# manylinux wheels, prebuilt npm native addons and glibc-only tools (T3 Code,
# Playwright/Chrome) run here as published; on musl they don't, or need compiling.
# Images built FROM this one install packages with apt, not apk. The 1.x Alpine
# Dockerfile is in git history and its images stay on GHCR. The paths, modes, user and
# USER/WORKDIR/ENTRYPOINT are the same as 1.x.
#
# No sshd, no SSH host keys, no authorized_keys injection: ECS Exec
# (enableExecuteCommand=True, src/warren/runtime/ecs.py) gives interactive access over SSM
# with nothing baked into the image and no exposed port — `aws ecs execute-command
# --interactive` attaches directly (confirmed: AWS injects the SSM agent into the task at
# the platform level, not the image). sshd exists in ../workspace-base specifically for
# Docker-backed workspaces reached over an exposed port on a remote host, where no
# SSM-equivalent exists. ECS has no such gap to fill, so this image doesn't carry the
# SSH/ACP-ForceCommand machinery at all.
#
# Base image: AWS's ECR Public Gallery mirror of Docker's official images, not Docker
# Hub — avoids Docker Hub's anonymous-pull rate limiting (same reasoning as
# warren-server's .github/workflows/warren-server-test.yml base-image pre-pull step) and
# keeps the pull inside AWS's own network for a task that's already running on AWS.
# debian:bookworm-slim, multi-arch index digest, as of 2026-10-31.
#
# BASE_REGISTRY only picks WHERE the digest-pinned bases are fetched from; the digests
# fix WHAT is built (BuildKit verifies the pulled content against them). CI passes an
# alternative (mirror.gcr.io/library, docker.io/library -- both verified to serve these
# identical index digests by .github/scripts/resolve-base-registry.sh) because anonymous
# ECR Public pulls from shared GitHub runner IPs intermittently fail with
# "toomanyrequests: Data limit exceeded". Local and default builds are unchanged.
ARG BASE_REGISTRY=public.ecr.aws/docker/library
FROM ${BASE_REGISTRY}/debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS base

# warren-secrets-decrypt (secrets-decrypt/): unwraps the KMS-encrypted secrets an
# EBS-backed task is launched with (src/warren/runtime/ecs_kms_secrets.py). Stdlib-only
# Go, static (CGO off), so the runtime image gains one small binary and no interpreter
# or AWS CLI, and the libc of the Go image doesn't matter. Its tests (incl. a vector
# produced by the control plane's own encrypt code) run here, so a broken helper fails
# the image build. Runs on the build platform and cross-compiles for the target
# (GOARCH): an arm64 host building linux/amd64 doesn't run Go under emulation, and vet
# and the tests run natively.
FROM --platform=$BUILDPLATFORM ${BASE_REGISTRY}/golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS secrets-decrypt
ARG TARGETARCH
WORKDIR /src
COPY packages/warren-server/images/ecs-base/secrets-decrypt/ ./
RUN go vet ./... \
    && go test ./... \
    && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/warren-secrets-decrypt .

# su-exec: privilege drop for entrypoint.sh, warren-session and git-init (AD3/AH1).
# bookworm doesn't package it, so this builds the same upstream release Alpine's su-exec
# package builds (ncopa/su-exec 0.2, aports main/su-exec; sha256 pinned below, the
# tarball matches Alpine's sha512 68155a06...d4e1), linked against glibc, on the target.
FROM ${BASE_REGISTRY}/debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS su-exec
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:ec4acbd8cde6ceeb2be67eda1f46c709758af6db35cacbcde41baac349855e25 \
    https://github.com/ncopa/su-exec/archive/refs/tags/v0.2.tar.gz /tmp/su-exec.tar.gz
RUN mkdir /tmp/su-exec && tar -xzf /tmp/su-exec.tar.gz -C /tmp/su-exec --strip-components=1 \
    && gcc -Wall -Werror -O2 -o /out-su-exec /tmp/su-exec/su-exec.c

FROM base

# su-exec comes from the stage above. openssh-client: git-init's ssh clones (AH1). The
# scripts run on Debian's dash, coreutils, findutils, sed, grep, mawk and tar. git is
# 2.39 on bookworm; every option git-materialize uses predates it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git openssh-client bash zsh tmux \
    && rm -rf /var/lib/apt/lists/* \
    # Debian's zsh runs zsh-newuser-install (an interactive menu) for a user with no
    # ~/.zshrc (1.x's Alpine zsh didn't), and the workspace's home has none, so remove it.
    && rm -f /usr/share/zsh/*/scripts/newuser

# su-exec at the 1.x (Alpine) path. Debian's /sbin is a symlink to /usr/sbin (merged /usr), so
# /sbin/su-exec, which entrypoint.sh, warren-session and git-init call, resolves here.
COPY --from=su-exec --chown=0:0 --chmod=0755 /out-su-exec /usr/sbin/su-exec

# AD3: non-root workspace user. uid/gid 1000 matches the EFS access point's PosixUser
# (src/warren/runtime/efs.py), so files under /var/lib/warren are owned by it. Home 2755
# with no skel files, /bin/bash, locked password (as 1.x's busybox `adduser -D` made it).
# /workspace is a real (empty) directory in the image. When the task has git folders
# (AH1), entrypoint.sh replaces it, as root and before dropping privileges, with a
# symlink to the checkout on the volume ($WARREN_WORKSPACE_DIR).
RUN groupadd -g 1000 warren \
    && useradd -u 1000 -g warren -M -d /home/warren -s /bin/bash -c 'Linux User,,,' warren \
    && mkdir -p /home/warren /workspace /var/lib/warren \
    && chmod 2755 /home/warren \
    && chown 1000:1000 /home/warren /workspace /var/lib/warren

# UX-1: warren's own prompt/banner, shared with the locally-written workspace
# .zshrc (packages/warren-cli/src/warren_cli/dispatch.py's
# _warren_banner_zsh_text) and warren-docker-base's own copy of this same
# file -- one definition instead of several that can drift. System-wide
# (/etc/zsh/zshrc) so it applies regardless of $HOME; it reads
# WARREN_PROJECT/WARREN_TEMPLATE/WARREN_WORKSPACE_ID from the environment at
# shell-start time (set by ECSRuntime.provision()'s containerOverrides), so
# this one image file works unmodified for every workspace that runs it.
COPY packages/warren-common/src/warren_common/assets/warren_banner.zsh /etc/zsh/zshrc
# AG2a: the template's harnesses as warren shell commands, plus `warren resume`, for zsh
# and bash. Generated from the harness profiles. Debian's bash reads /etc/bash.bashrc,
# so the hooks go there; /etc/bash/bashrc (1.x's Alpine path) links to it for images
# that append to that path.
COPY --chown=0:0 --chmod=0644 packages/warren-common/src/warren_common/assets/warren_harness.sh /etc/warren/harness.sh
COPY --chown=0:0 --chmod=0644 packages/warren-common/src/warren_common/assets/warren_banner.bash /etc/warren/banner.bash
RUN printf '\n[ -r /etc/warren/harness.sh ] && . /etc/warren/harness.sh\n' >> /etc/zsh/zshrc \
    && printf '\n[ -r /etc/warren/banner.bash ] && . /etc/warren/banner.bash\n[ -r /etc/warren/harness.sh ] && . /etc/warren/harness.sh\n' >> /etc/bash.bashrc \
    && mkdir -p /etc/bash \
    && ln -s ../bash.bashrc /etc/bash/bashrc

# Root-owned 0755 in root-owned dirs: ECS Exec runs warren-session as root, and the CLI
# refuses to run it otherwise (dispatch.ecs_session_command). git-init (AH1) runs
# warren-git-materialize as root; it runs warren-init-volume, then drops to warren.
COPY --chown=0:0 --chmod=0755 packages/warren-server/images/ecs-base/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=0:0 --chmod=0755 packages/warren-server/images/ecs-base/warren-session.sh /usr/local/bin/warren-session
COPY --chown=0:0 --chmod=0755 packages/warren-server/images/ecs-base/warren-init-volume.sh /usr/local/bin/warren-init-volume
# AB1/AG3: prunes harness dirs to their persist paths and rewrites generated config at start.
COPY --chown=0:0 --chmod=0755 packages/warren-common/src/warren_common/assets/warren_harness_init.sh /usr/local/bin/warren-harness-init
# AG5: the state hook the harness hook configs call (root-owned, read-only to the workspace).
COPY --chown=0:0 --chmod=0755 packages/warren-common/src/warren_common/assets/warren_state_hook.sh /usr/local/bin/warren-state-hook
COPY --chown=0:0 --chmod=0755 packages/warren-common/src/warren_common/agent_supervisor.py /usr/local/bin/warren-agent-supervisor
# AH1: run as the task's `git-init` container (runtime/ecs_git.py), never by the workspace.
COPY --chown=0:0 --chmod=0755 packages/warren-server/images/ecs-base/git-materialize.sh /usr/local/bin/warren-git-materialize
# Reader for the secrets file the control plane drops on the EFS volume (runtime/ecs_secrets.py),
# and for warren-secrets-decrypt's output in EBS mode, sourced by entrypoint.sh, warren-session and warren-git-materialize.
COPY --chown=0:0 --chmod=0644 packages/warren-server/images/ecs-base/warren-secrets.sh /usr/local/lib/warren/secrets.sh
# EBS mode: decrypts WARREN_SECRETS_BLOB for entrypoint.sh / warren-git-materialize.
COPY --from=secrets-decrypt --chown=0:0 --chmod=0755 /out/warren-secrets-decrypt /usr/local/bin/warren-secrets-decrypt
# GitHub's published SSH host keys (api.github.com/meta "ssh_keys"), pinned for git-init's
# ssh clones. Refresh the checked-in file when GitHub rotates a key.
COPY --chown=0:0 --chmod=0444 packages/warren-server/images/ecs-base/ssh_known_hosts /etc/warren/ssh_known_hosts
# git_write templates (src/warren/git/write_tokens.py): warren-git-token installs the
# control plane's repo-scoped GitHub tokens in /run/warren-git (as root: entrypoint, ECS
# Exec); git-credential-warren hands them to git for https://github.com only.
COPY --chown=0:0 --chmod=0755 packages/warren-server/images/ecs-base/warren-git-token.sh /usr/local/bin/warren-git-token
COPY --chown=0:0 --chmod=0755 packages/warren-common/src/warren_common/assets/warren_git_credential.sh /usr/local/bin/git-credential-warren
RUN git config --system credential.https://github.com.helper /usr/local/bin/git-credential-warren \
    && git config --system credential.https://github.com.useHttpPath true
RUN chown 0:0 /usr /usr/local /usr/local/bin /usr/local/lib /usr/local/lib/warren /etc/warren \
    && chmod 0755 /usr /usr/local /usr/local/bin /usr/local/lib /usr/local/lib/warren /etc/warren

# C.UTF-8 so tmux, zsh and the TUIs draw box characters (Debian's slim image sets no locale).
ENV LANG=C.UTF-8

# The container starts as root so entrypoint.sh can take ownership of a fresh task volume
# mount point, then it drops to warren (uid 1000) before running anything else. Extension
# images must leave USER as root (or unset); the drop happens in the entrypoint.
USER root
WORKDIR /home/warren

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# No CMD — set by extension images layering real agent tooling on top (same convention as
# ../workspace-base and images/warren-docker-base).
