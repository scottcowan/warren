# syntax=docker/dockerfile:1.7
# ecs-base — minimal workspace image for ECS-backed workspaces (D-10 sibling to
# ../workspace-base, which targets Docker instead — see that Containerfile's own header).
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
# Base image: AWS's ECR Public Gallery mirror of Alpine, not Docker Hub — avoids Docker
# Hub's anonymous-pull rate limiting (same reasoning as warren-server's
# .github/workflows/warren-server-test.yml base-image pre-pull step) and keeps the pull
# inside AWS's own network for a task that's already running on AWS.
# 3.20 as of 2026-10-17 (a trailing comment on the FROM line itself is invalid
# Dockerfile syntax -- "FROM requires either one or three arguments" -- audit S1)
#
# BASE_REGISTRY only picks WHERE the digest-pinned base is fetched from; the digest itself
# fixes WHAT is built (BuildKit verifies the pulled content against it). CI passes an
# alternative (mirror.gcr.io/library, docker.io/library -- both verified to serve this
# identical index digest by .github/scripts/resolve-base-registry.sh) because anonymous
# ECR Public pulls from shared GitHub runner IPs intermittently fail with
# "toomanyrequests: Data limit exceeded". Local and default builds are unchanged.
ARG BASE_REGISTRY=public.ecr.aws/docker/library
FROM ${BASE_REGISTRY}/alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

# su-exec: privilege drop for entrypoint.sh, warren-session and git-init (AD3/AH1).
# openssh-client: git-init's ssh clones (AH1).
RUN apk add --no-cache ca-certificates git openssh-client bash zsh tmux su-exec

# AD3: non-root workspace user. uid/gid 1000 matches the EFS access point's PosixUser
# (src/warren/runtime/efs.py), so files under /var/lib/warren are owned by it.
# /workspace is a real (empty) directory in the image. When the task has git folders
# (AH1), entrypoint.sh replaces it, as root and before dropping privileges, with a
# symlink to the checkout on the volume ($WARREN_WORKSPACE_DIR).
RUN addgroup -g 1000 warren \
    && adduser -D -u 1000 -G warren -h /home/warren -s /bin/bash warren \
    && mkdir -p /workspace /var/lib/warren \
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
# and bash (alpine's bash reads /etc/bash/bashrc). Generated from the harness profiles.
COPY --chown=0:0 --chmod=0644 packages/warren-common/src/warren_common/assets/warren_harness.sh /etc/warren/harness.sh
COPY --chown=0:0 --chmod=0644 packages/warren-common/src/warren_common/assets/warren_banner.bash /etc/warren/banner.bash
RUN printf '\n[ -r /etc/warren/harness.sh ] && . /etc/warren/harness.sh\n' >> /etc/zsh/zshrc \
    && mkdir -p /etc/bash \
    && printf '\n[ -r /etc/warren/banner.bash ] && . /etc/warren/banner.bash\n[ -r /etc/warren/harness.sh ] && . /etc/warren/harness.sh\n' >> /etc/bash/bashrc

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
# Reader for the secrets file the control plane drops on the volume (runtime/ecs_secrets.py),
# sourced by entrypoint.sh, warren-session and warren-git-materialize.
COPY --chown=0:0 --chmod=0644 packages/warren-server/images/ecs-base/warren-secrets.sh /usr/local/lib/warren/secrets.sh
# GitHub's published SSH host keys (api.github.com/meta "ssh_keys"), pinned for git-init's
# ssh clones. Refresh the checked-in file when GitHub rotates a key.
COPY --chown=0:0 --chmod=0444 packages/warren-server/images/ecs-base/ssh_known_hosts /etc/warren/ssh_known_hosts
RUN chown 0:0 /usr /usr/local /usr/local/bin /usr/local/lib /usr/local/lib/warren \
    && chmod 0755 /usr /usr/local /usr/local/bin /usr/local/lib /usr/local/lib/warren

# The container starts as root so entrypoint.sh can take ownership of a fresh task volume
# mount point, then it drops to warren (uid 1000) before running anything else. Extension
# images must leave USER as root (or unset); the drop happens in the entrypoint.
USER root
WORKDIR /home/warren

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# No CMD — set by extension images layering real agent tooling on top (same convention as
# ../workspace-base and images/warren-docker-base).
