# syntax=docker/dockerfile:1.7
# ecs-t3code: an EXAMPLE ECS workspace image that runs T3 Code's server (`t3 serve`,
# https://t3.codes) next to Claude Code. Not published and not built by CI: no workflow
# builds it and it isn't a component in .github/releases.json. Build it yourself
# (README.md).
#
# Why Debian and not FROM warren-ecs-base: T3 Code's prebuilt server is glibc-only.
# On Alpine, even with gcompat, it dies with `fcntl64: symbol not found`. So this image
# rebuilds ecs-base's workspace contract on Debian bookworm: the same files at the same
# paths and modes, the same uid/gid 1000 user and directories, USER root,
# WORKDIR /home/warren and the same ENTRYPOINT. The warren files are copied out of the
# published, digest-pinned ecs-base image. Two pieces can't come from it:
#   - su-exec: Alpine's is musl-linked, and bookworm doesn't package su-exec. It's built
#     here from the same upstream release Alpine packages (ncopa/su-exec 0.2, checked
#     against Alpine's sha512).
#   - warren-secrets-decrypt: ecs-base is published for linux/amd64 only. It's built
#     here from the ecs-base release commit with ecs-base's own Go image and flags. On
#     amd64 the build fails unless the result is byte-identical to the published binary.
#
# Multi-arch through TARGETARCH (linux/arm64, linux/amd64). Download stages run on the
# build platform; only the final stage and the su-exec compile run on the target.

ARG BASE_REGISTRY=public.ecr.aws/docker/library
# debian:bookworm-slim, multi-arch index digest, as of 2026-10-31.
ARG DEBIAN_IMAGE=${BASE_REGISTRY}/debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
# warren-ecs-base-v1.4.0 (commit 3a0dbddf74b405c4115249d8ebf0caf7d921712c), index digest.
ARG WARREN_ECS_BASE=ghcr.io/scottcowan/warren-ecs-base:1.4.0@sha256:43b4196aab501970b8dfed790fa8ce3e7d9bb0d47debbc527b6366712cc202b7
ARG WARREN_ECS_BASE_COMMIT=3a0dbddf74b405c4115249d8ebf0caf7d921712c

# Only linux/amd64 is published. Everything taken from it except the Go binary is a
# script or data file, so the platform doesn't matter for those.
FROM --platform=linux/amd64 ${WARREN_ECS_BASE} AS ecs-base

# warren-secrets-decrypt from the ecs-base release commit, same Go image (by digest),
# tests and flags as packages/warren-server/images/ecs-base/Dockerfile, cross-compiled
# for the target.
FROM --platform=$BUILDPLATFORM ${BASE_REGISTRY}/golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS secrets-decrypt
ARG TARGETARCH
ARG WARREN_ECS_BASE_COMMIT
ADD --keep-git-dir=false https://github.com/scottcowan/warren.git#${WARREN_ECS_BASE_COMMIT}:packages/warren-server/images/ecs-base/secrets-decrypt /src
COPY --from=ecs-base /usr/local/bin/warren-secrets-decrypt /published/warren-secrets-decrypt
WORKDIR /src
RUN go vet ./... \
    && go test ./... \
    && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false -ldflags='-s -w' -o /out/warren-secrets-decrypt . \
    && if [ "${TARGETARCH}" = amd64 ]; then \
         cmp /out/warren-secrets-decrypt /published/warren-secrets-decrypt \
           || { echo "warren-secrets-decrypt built from ${WARREN_ECS_BASE_COMMIT} differs from the published ecs-base binary" >&2; exit 1; }; \
       fi

# su-exec 0.2: the upstream release Alpine's su-exec package builds (aports main/su-exec,
# sha512 68155a06...d4e1 for this same tarball). Built for glibc on the target.
FROM ${DEBIAN_IMAGE} AS su-exec
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:ec4acbd8cde6ceeb2be67eda1f46c709758af6db35cacbcde41baac349855e25 \
    https://github.com/ncopa/su-exec/archive/refs/tags/v0.2.tar.gz /tmp/su-exec.tar.gz
RUN mkdir /tmp/su-exec && tar -xzf /tmp/su-exec.tar.gz -C /tmp/su-exec --strip-components=1 \
    && gcc -Wall -Werror -O2 -o /out-su-exec /tmp/su-exec/su-exec.c

# Downloads: Claude Code and t3, each checked against a published checksum, for the
# target architecture. Nothing here reaches the final image except the two installs.
FROM --platform=$BUILDPLATFORM ${DEBIAN_IMAGE} AS fetch
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg jq \
    && rm -rf /var/lib/apt/lists/*

# Claude Code, verified the same way as packages/warren-server/images/warren-ecs-dev-base:
# Anthropic's GPG-signed manifest.json (key fingerprint
# 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE, security@anthropic.com) carries a sha256 per
# platform binary. One difference: the binary comes straight from the release bucket
# install.sh downloads from (downloads.claude.ai/claude-code-releases/<version>/<platform>/claude)
# instead of through install.sh. So there's no unpinned script, no root-home symlink
# (ecs-dev-base's R26/S12 (c) landmine), and it lands directly in /usr/local/bin.
# linux-{arm64,x64} are the glibc builds; the -musl ones are for Alpine.
ARG CLAUDE_CODE_VERSION=2.1.308
RUN case "${TARGETARCH}" in \
         amd64) _CC_PLATFORM=linux-x64 ;; \
         arm64) _CC_PLATFORM=linux-arm64 ;; \
         *) echo "unsupported TARGETARCH for Claude Code: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && _CC_REPO="https://downloads.claude.ai/claude-code-releases" \
    && _CC_DIR="$(mktemp -d)" \
    && curl -fsSL https://downloads.claude.ai/keys/claude-code.asc -o "${_CC_DIR}/claude-code.asc" \
    && export GNUPGHOME="${_CC_DIR}/gnupg" && mkdir -m 700 "${GNUPGHOME}" \
    && gpg --batch --import "${_CC_DIR}/claude-code.asc" \
    && gpg --batch --fingerprint security@anthropic.com | grep -q "31DD DE24 DDFA B679 F42D  7BD2 BAA9 29FF 1A7E CACE" \
    && curl -fsSLo "${_CC_DIR}/manifest.json" "${_CC_REPO}/${CLAUDE_CODE_VERSION}/manifest.json" \
    && curl -fsSLo "${_CC_DIR}/manifest.json.sig" "${_CC_REPO}/${CLAUDE_CODE_VERSION}/manifest.json.sig" \
    && gpg --batch --verify "${_CC_DIR}/manifest.json.sig" "${_CC_DIR}/manifest.json" \
    && _CC_EXPECTED="$(jq -r ".platforms[\"${_CC_PLATFORM}\"].checksum" "${_CC_DIR}/manifest.json")" \
    && curl -fsSLo /out-claude "${_CC_REPO}/${CLAUDE_CODE_VERSION}/${_CC_PLATFORM}/claude" \
    && _CC_ACTUAL="$(sha256sum /out-claude | cut -d' ' -f1)" \
    && if [ -z "${_CC_EXPECTED}" ] || [ "${_CC_EXPECTED}" = null ] || [ "${_CC_EXPECTED}" != "${_CC_ACTUAL}" ]; then \
         echo "Claude Code binary checksum mismatch for ${_CC_PLATFORM} ${CLAUDE_CODE_VERSION}: expected ${_CC_EXPECTED}, got ${_CC_ACTUAL}" >&2; \
         exit 1; \
       fi \
    && chmod 0755 /out-claude \
    && rm -rf "${_CC_DIR}"

# t3: the release archive install.sh (https://t3.codes/install.sh) downloads,
# github.com/pingdotgg/t3code/releases/download/v<version>/t3-<version>-linux-<arch>.tar.gz.
# The sha256s below match the release's SHA256SUMS and GitHub's asset digests for v0.1.6.
# They're pinned here rather than read from SHA256SUMS at build time, which would only
# prove the two downloads match each other. The archive is a directory (the t3 executable
# plus the native node_modules it loads), kept together under /opt/t3/<version>.
ARG T3_VERSION=0.1.6
ARG T3_SHA256_ARM64=b708f059200776f50623a766854841e40eda0bb67614211cf8b6909295ce20da
ARG T3_SHA256_AMD64=7cf31da90dee41f524dd5b679ebb6d404637ca5d9dc6fd8bc019511d57bb77e6
RUN case "${TARGETARCH}" in \
         amd64) _T3_ARCH=x64; _T3_SHA256="${T3_SHA256_AMD64}" ;; \
         arm64) _T3_ARCH=arm64; _T3_SHA256="${T3_SHA256_ARM64}" ;; \
         *) echo "unsupported TARGETARCH for t3: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && _T3_ARCHIVE="t3-${T3_VERSION}-linux-${_T3_ARCH}.tar.gz" \
    && curl -fsSLo "/tmp/${_T3_ARCHIVE}" "https://github.com/pingdotgg/t3code/releases/download/v${T3_VERSION}/${_T3_ARCHIVE}" \
    && echo "${_T3_SHA256}  /tmp/${_T3_ARCHIVE}" | sha256sum -c - \
    && mkdir -p "/out-t3/${T3_VERSION}" \
    && tar -xzf "/tmp/${_T3_ARCHIVE}" -C "/out-t3/${T3_VERSION}" --strip-components=1 --no-same-owner \
    && test -x "/out-t3/${T3_VERSION}/t3" \
    && chmod -R u=rwX,go=rX /out-t3 \
    && rm "/tmp/${_T3_ARCHIVE}"

FROM ${DEBIAN_IMAGE}
ARG T3_VERSION=0.1.6

# ecs-base's apk set (ca-certificates git openssh-client bash zsh tmux) plus what this
# example adds: curl, python3 (warren-agent-supervisor for `kind: agent` workspaces;
# bookworm's is 3.11, warren-common needs >=3.11), jq, ripgrep. Debian's coreutils,
# findutils, sed, grep, mawk, tar and dash stand in for busybox; the warren
# scripts only use POSIX options of those (README.md, "Debian vs Alpine").
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git openssh-client bash zsh tmux curl python3 jq ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    # Debian's zsh runs zsh-newuser-install (an interactive menu) for a user with no
    # ~/.zshrc. Alpine's doesn't, and the workspace's home has none, so remove it.
    && rm -f /usr/share/zsh/*/scripts/newuser

# su-exec at Alpine's path. Debian's /sbin is a symlink to /usr/sbin (merged /usr), so
# /sbin/su-exec, which entrypoint.sh, warren-session and git-init call, resolves here.
COPY --from=su-exec --chown=0:0 --chmod=0755 /out-su-exec /usr/sbin/su-exec

# AD3: uid/gid 1000 warren, home /home/warren (setgid 2755 like busybox adduser's),
# /bin/bash, locked password, no /etc/skel files (Alpine's adduser copies none), and
# /workspace + /var/lib/warren owned by 1000. Same as ecs-base.
RUN groupadd -g 1000 warren \
    && useradd -u 1000 -g warren -M -d /home/warren -s /bin/bash -c 'Linux User,,,' warren \
    && mkdir -p /home/warren /workspace /var/lib/warren \
    && chmod 2755 /home/warren \
    && chown 1000:1000 /home/warren /workspace /var/lib/warren

# UX-1 / AG2a shell hooks, from ecs-base. zsh reads /etc/zsh/zshrc on Debian too: the
# file is copied whole (banner + harness hook). Debian's bash reads /etc/bash.bashrc,
# not Alpine's /etc/bash/bashrc, so the same two lines ecs-base appends there are
# appended to Debian's file; /etc/bash/bashrc links to it so the ecs-base path exists.
COPY --from=ecs-base --chown=0:0 --chmod=0644 /etc/zsh/zshrc /etc/zsh/zshrc
COPY --from=ecs-base --chown=0:0 --chmod=0644 /etc/warren/harness.sh /etc/warren/harness.sh
COPY --from=ecs-base --chown=0:0 --chmod=0644 /etc/warren/banner.bash /etc/warren/banner.bash
COPY --from=ecs-base --chown=0:0 --chmod=0444 /etc/warren/ssh_known_hosts /etc/warren/ssh_known_hosts
RUN printf '\n[ -r /etc/warren/banner.bash ] && . /etc/warren/banner.bash\n[ -r /etc/warren/harness.sh ] && . /etc/warren/harness.sh\n' >> /etc/bash.bashrc \
    && mkdir -p /etc/bash /etc/zsh/zshrc.d \
    && ln -s ../bash.bashrc /etc/bash/bashrc \
    # ecs-base 1.4.0 ships /etc/warren as 0644 (no search bit), so uid 1000 can't read
    # banner.bash or harness.sh and the warren shell commands are missing for it. Use
    # 0755, which is what the rc hooks above need.
    && chmod 0755 /etc/warren

# Root-owned 0755 helpers in root-owned 0755 dirs, same paths as ecs-base (the CLI's ECS
# Exec command refuses to run warren-session otherwise).
COPY --from=ecs-base --chown=0:0 --chmod=0755 /usr/local/bin/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --from=ecs-base --chown=0:0 --chmod=0755 /usr/local/bin/warren-session /usr/local/bin/warren-session
COPY --from=ecs-base --chown=0:0 --chmod=0755 /usr/local/bin/warren-init-volume /usr/local/bin/warren-init-volume
COPY --from=ecs-base --chown=0:0 --chmod=0755 /usr/local/bin/warren-harness-init /usr/local/bin/warren-harness-init
COPY --from=ecs-base --chown=0:0 --chmod=0755 /usr/local/bin/warren-state-hook /usr/local/bin/warren-state-hook
COPY --from=ecs-base --chown=0:0 --chmod=0755 /usr/local/bin/warren-agent-supervisor /usr/local/bin/warren-agent-supervisor
COPY --from=ecs-base --chown=0:0 --chmod=0755 /usr/local/bin/warren-git-materialize /usr/local/bin/warren-git-materialize
COPY --from=ecs-base --chown=0:0 --chmod=0644 /usr/local/lib/warren/secrets.sh /usr/local/lib/warren/secrets.sh
COPY --from=secrets-decrypt --chown=0:0 --chmod=0755 /out/warren-secrets-decrypt /usr/local/bin/warren-secrets-decrypt

# Claude Code and t3, root-owned, on PATH for every user.
COPY --from=fetch --chown=0:0 --chmod=0755 /out-claude /usr/local/bin/claude
COPY --from=fetch --chown=0:0 /out-t3/ /opt/t3/
RUN ln -s "/opt/t3/${T3_VERSION}/t3" /usr/local/bin/t3 \
    && chown 0:0 /opt /opt/t3 /usr /usr/local /usr/local/bin /usr/local/lib /usr/local/lib/warren \
    && chmod 0755 /opt /opt/t3 /usr /usr/local /usr/local/bin /usr/local/lib /usr/local/lib/warren \
    && t3 --version && claude --version

# C.UTF-8 so tmux, zsh and the TUIs draw box characters (Debian's slim image sets no locale).
# Claude Code: the binary is root-owned in /usr/local/bin, so its auto-updater can only
# fail; rebuild with a new CLAUDE_CODE_VERSION instead. t3: `t3 serve` started directly
# (not `t3 service install`) has no service launcher, so the server refuses remote
# updates from the apps. T3CODE_TELEMETRY_ENABLED=false stops its product-usage events
# (hashed account ids) and relay traces; unset it in the template env to opt back in.
ENV LANG=C.UTF-8 \
    DISABLE_AUTOUPDATER=1 \
    T3CODE_TELEMETRY_ENABLED=false

# Same as ecs-base: start as root so entrypoint.sh can take ownership of a fresh task
# volume, then it drops to warren (uid 1000). Leave USER as root.
USER root
WORKDIR /home/warren

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# No CMD, like ecs-base: entrypoint.sh only runs WARREN_APP_CMD (or idles).
