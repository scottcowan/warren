# syntax=docker/dockerfile:1.7
# ecs-t3code: an EXAMPLE ECS workspace image that runs T3 Code's server (`t3 serve`,
# https://t3.codes) next to Claude Code. Not published and not built by CI: no workflow
# builds it and it isn't a component in .github/releases.json. Build it yourself
# (README.md).
#
# FROM warren-ecs-base 1.5.0 or later, the first Debian (glibc) release. T3 Code's
# prebuilt server is glibc-only (on the 1.4 and earlier Alpine images, even with gcompat, it dies
# with `fcntl64: symbol not found`). Everything warren needs (entrypoint, warren-session,
# git-init, secrets handling, su-exec, the uid/gid 1000 user, USER root, WORKDIR,
# ENTRYPOINT) comes from ecs-base unchanged; this image only adds packages, Claude Code
# and t3.
#
# Multi-arch through TARGETARCH (linux/arm64, linux/amd64). The download stage runs on
# the build platform; only the final stage runs on the target.

ARG BASE_REGISTRY=public.ecr.aws/docker/library
# debian:bookworm-slim, multi-arch index digest, as of 2026-10-31: the base
# warren-ecs-base 1.5.0 uses. Only the download stage runs on it.
ARG DEBIAN_IMAGE=${BASE_REGISTRY}/debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3
# warren-ecs-base 1.5.0, pinned by digest. To build against a locally built ecs-base, pass
# --build-arg WARREN_ECS_BASE=<local tag> (README.md, "Build").
ARG WARREN_ECS_BASE=ghcr.io/scottcowan/warren-ecs-base:1.5.0@sha256:090ae2f6cde680cbc48a7b5df5a54f77143897301e320a3e373b6e9b0126165e

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
# linux-{arm64,x64} are the glibc builds.
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

FROM ${WARREN_ECS_BASE}
ARG T3_VERSION=0.1.6

# What this example adds to ecs-base: curl, python3 (warren-agent-supervisor for
# `kind: agent` workspaces; bookworm's is 3.11, warren-common needs >=3.11), jq, ripgrep.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl python3 jq ripgrep \
    && rm -rf /var/lib/apt/lists/*

# Claude Code and t3, root-owned, on PATH for every user.
COPY --from=fetch --chown=0:0 --chmod=0755 /out-claude /usr/local/bin/claude
COPY --from=fetch --chown=0:0 /out-t3/ /opt/t3/
RUN ln -s "/opt/t3/${T3_VERSION}/t3" /usr/local/bin/t3 \
    && chown 0:0 /opt /opt/t3 \
    && chmod 0755 /opt /opt/t3 \
    && t3 --version && claude --version

# Claude Code: the binary is root-owned in /usr/local/bin, so its auto-updater can only
# fail; rebuild with a new CLAUDE_CODE_VERSION instead. t3: `t3 serve` started directly
# (not `t3 service install`) has no service launcher, so the server refuses remote
# updates from the apps. T3CODE_TELEMETRY_ENABLED=false stops its product-usage events
# (hashed account ids) and relay traces; unset it in the template env to opt back in.
# LANG=C.UTF-8 comes from ecs-base.
ENV DISABLE_AUTOUPDATER=1 \
    T3CODE_TELEMETRY_ENABLED=false

# USER root, WORKDIR /home/warren, ENTRYPOINT and no CMD are inherited from ecs-base:
# entrypoint.sh starts as root, takes ownership of a fresh task volume, then drops to
# warren (uid 1000). Leave USER as root.
