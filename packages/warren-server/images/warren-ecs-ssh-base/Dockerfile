# syntax=docker/dockerfile:1.7
# warren-ecs-ssh-base — opt-in layer on top of warren-ecs-dev-base that adds an sshd for
# editor remoting (VS Code Remote-SSH, Cursor, JetBrains Gateway). Published as
# ghcr.io/scottcowan/warren-ecs-ssh-base. See docs/workspace-ssh.md.
#
# ecs-base and dev-base deliberately ship no sshd: ECS Exec over SSM is the interactive
# path (../ecs-base/Dockerfile's header). This image keeps that model. Its sshd:
#   - listens on 127.0.0.1:2222 only. A Fargate task has no inbound path to it; the
#     client reaches it through an SSM port-forward to the task's loopback
#     (`warren proxy stdio <ws> 2222` as an ssh ProxyCommand, `warren ssh-config <ws>`),
#     which needs ssm:StartSession on the task, the same permission ECS Exec needs;
#   - runs as the workspace user (uid 1000), started after the entrypoint dropped
#     privileges, so it has nothing the workload doesn't already have;
#   - takes public keys only, for the `warren` user only, with local TCP forwarding
#     only (no X11, agent, remote or Unix-socket forwarding; see sshd_config);
#   - has no host key in the image: warren-sshd generates one on first start onto the
#     workspace volume, so it persists across restarts and known_hosts stays valid.
# Nothing changes for ecs-base or dev-base, and nothing here runs unless a template
# uses this image.
#
# WARREN_ECS_DEV_BASE: the dev-base image this layers on. It names the 1.3.0 release by
# tag (the first Debian dev-base, built FROM warren-ecs-base 1.5.0) because that isn't
# published yet; pin it by digest (tag@sha256:...) once it is, as
# ../warren-ecs-agent-base pins dev-base. The smoke workflow builds ecs-base and
# dev-base from the same commit and passes them in, so the three are tested together.
ARG WARREN_ECS_DEV_BASE=ghcr.io/scottcowan/warren-ecs-dev-base:1.3.0
FROM ${WARREN_ECS_DEV_BASE}

# openssh-server from Debian's archive. Its postinst generates host keys under
# /etc/ssh; they are deleted so no image (and so no two workspaces) share a host key.
# Debian's default sshd_config is replaced by this image's own, and the drop-in
# directory is emptied so only what a derived image adds there applies.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* \
    && rm -rf /etc/ssh/sshd_config.d \
    && mkdir -m 0755 /etc/ssh/sshd_config.d

COPY --chown=0:0 --chmod=0644 sshd_config /etc/ssh/sshd_config
COPY --chown=0:0 --chmod=0755 warren-sshd.sh /usr/local/bin/warren-sshd
# The wrapper takes ecs-base's entrypoint path (the base entrypoint re-execs that path
# as uid 1000 after the privilege drop, which is where sshd starts); the base
# entrypoint itself moves, unchanged, next to the other warren helpers.
RUN mv /usr/local/bin/entrypoint.sh /usr/local/lib/warren/ecs-entrypoint.sh
COPY --chown=0:0 --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh

# SSH logins get a clean login environment, and Debian's /etc/profile resets PATH, so
# put the image's own PATH (pyenv shims, /usr/local) back for them.
RUN printf 'PATH="%s"\nexport PATH\n' "${PATH}" > /etc/profile.d/warren-path.sh \
    && chmod 0644 /etc/profile.d/warren-path.sh

# herdr (https://herdr.dev), a terminal workspace manager for AI agents. `herdr machine
# add <ssh-alias>` over this sshd runs its own server in the workspace and shows its
# panes next to the local ones. Pinned release, per-arch sha256 checked at build time
# (the digests GitHub lists for the v0.9.5 release assets), root-owned 0755. Never run
# `herdr update` inside the image: it would replace a verified binary with an unpinned
# one; bump HERDR_VERSION and both checksums here instead.
# Update checks: herdr reads HERDR_CONFIG_PATH, so a root-owned /etc/herdr/config.toml
# turns off the background version and manifest checks for login shells (profile.d).
# Non-login ssh commands don't read profile.d; the same two keys in
# ~/.config/herdr/config.toml (on the volume) cover those.
ARG TARGETARCH
ARG HERDR_VERSION=0.9.5
ARG HERDR_SHA256_AMD64=14d9e8bc8b4a9e0118d77c32266f76d461f09b40342eb23752960bd89f59929d
ARG HERDR_SHA256_ARM64=17d7536f2da50859523680ef279dffcac8e4a235f4e46fe8da6c2ec44141897c
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
        amd64) asset=herdr-linux-x86_64; sum="${HERDR_SHA256_AMD64}" ;; \
        arm64) asset=herdr-linux-aarch64; sum="${HERDR_SHA256_ARM64}" ;; \
        *) echo "herdr: unsupported architecture ${TARGETARCH:-?}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 3 -o /tmp/herdr "https://github.com/herdrdev/herdr/releases/download/v${HERDR_VERSION}/${asset}"; \
    echo "${sum}  /tmp/herdr" | sha256sum -c -; \
    install -o root -g root -m 0755 /tmp/herdr /usr/local/bin/herdr; \
    rm -f /tmp/herdr; \
    mkdir -p /etc/herdr; \
    printf '[update]\nversion_check = false\nmanifest_check = false\n' > /etc/herdr/config.toml; \
    chmod 0644 /etc/herdr/config.toml; \
    printf 'HERDR_CONFIG_PATH=/etc/herdr/config.toml\nexport HERDR_CONFIG_PATH\n' > /etc/profile.d/warren-herdr.sh; \
    chmod 0644 /etc/profile.d/warren-herdr.sh; \
    herdr --version

# The config parses, checked the way it runs (as uid 1000) with a throwaway host key.
RUN su-exec warren sh -c "ssh-keygen -q -t ed25519 -N '' -f /tmp/k && /usr/sbin/sshd -t -f /etc/ssh/sshd_config -h /tmp/k" \
    && rm -f /tmp/k /tmp/k.pub
