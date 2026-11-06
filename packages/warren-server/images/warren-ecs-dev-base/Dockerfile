# syntax=docker/dockerfile:1.7
# warren-ecs-dev-base — convenience layer on top of ecs-base, NOT a fork of it (same
# pattern as ../../../../images/warren-dev-base, the Docker-env counterpart). Gets the
# agent harnesses (Claude Code, codex, pi) plus common dev tools preinstalled, without
# touching ecs-base's own minimal, no-sshd, no-harness design (see ../ecs-base/Dockerfile's
# header). opencode is in the Docker-env dev-base only (docs/harnesses.md).
#
# Debian bookworm (glibc) since 1.3.0, because warren-ecs-base 1.5.0 is; 1.2 and earlier were Alpine.
# Packages come from apt. Node is nodejs.org's official linux tarball (glibc-linked, so
# prebuilt npm native addons load), the AWS CLI is AWS's official v2 installer (Debian's
# `awscli` package is v1), Python is pyenv-compiled, and Claude Code is the glibc build.
# Each harness binary is root-owned and on PATH in /usr/local/bin, with its self-update
# turned off (the ENV block after the installs).
# Multi-arch through TARGETARCH (linux/amd64, linux/arm64); the published image is
# linux/amd64 (.github/workflows/warren-ecs-dev-base-image.yml).
#
# Trust boundary: Debian's apt archive, nodejs.org's tarball (sha256 pinned below from
# the release's SHASUMS256.txt), AWS's CLI installer zip (its detached PGP signature
# checked against the AWS CLI Team key checked in next to this file, fingerprint
# asserted in the install step below), pyenv's install script (fetched over HTTPS
# from its official GitHub repo, pinned to a commit and checksum), and Anthropic's own
# native installer (`curl https://claude.ai/install.sh | bash`, pinned to an exact
# version — NOT the npm package `@anthropic-ai/claude-code`; see the Claude Code install
# RUN step below for why). The installed binary's own integrity is checked against
# Anthropic's GPG-signed release manifest (R26/S12) -- the install.sh *script* fetch
# itself remains TOFU-only (no published checksum for that script exists to pin
# against), a known, deliberately-unresolved broader supply-chain gap this audit
# already tracks separately. codex: OpenAI's GitHub release tarball for this
# architecture (version and sha256 pinned below, the sha256 from GitHub's asset digest).
# pi: the npm registry, through `npm ci` against the lockfile checked in under pi/
# (every package pinned by version and sha512 integrity; no install scripts run).
#
# WARREN_ECS_BASE: the ecs-base image this layers on. It names the 1.5.0 release by tag
# because that's the first Debian release and it isn't published yet; pin it by digest
# (tag@sha256:...) once it is. The smoke workflow builds ecs-base from the same commit and
# passes it here, so the two are always tested together.
ARG WARREN_ECS_BASE=ghcr.io/scottcowan/warren-ecs-base:1.5.0
FROM ${WARREN_ECS_BASE}
ARG TARGETARCH

# ca-certificates/git/bash already present from ecs-base.
# build-essential + pyenv's documented Debian build deps (source compile).
# gnupg: verifies Anthropic's signed release manifest for the Claude Code binary
# (R26/S12 below) and the AWS CLI installer's signature.
# xz-utils/unzip: the Node tarball and the AWS CLI zip.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        curl jq gnupg ripgrep unzip xz-utils \
        build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
        libncursesw5-dev tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev \
    && rm -rf /var/lib/apt/lists/*

# Node.js LTS from nodejs.org, into /usr/local (node, npm, npx, corepack on PATH). The
# sha256s are the release's SHASUMS256.txt entries for these two tarballs.
ARG NODE_VERSION=24.22.2
ARG NODE_SHA256_AMD64=48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75
ARG NODE_SHA256_ARM64=eb187837a2230d4047161ac0be008584e16b46f726e9c9490ee35dc6b17d9ba8
RUN case "${TARGETARCH}" in \
         amd64) _NODE_ARCH=x64; _NODE_SHA256="${NODE_SHA256_AMD64}" ;; \
         arm64) _NODE_ARCH=arm64; _NODE_SHA256="${NODE_SHA256_ARM64}" ;; \
         *) echo "unsupported TARGETARCH for Node.js: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && _NODE_TARBALL="node-v${NODE_VERSION}-linux-${_NODE_ARCH}.tar.xz" \
    && curl -fsSL --retry 3 -o "/tmp/${_NODE_TARBALL}" "https://nodejs.org/dist/v${NODE_VERSION}/${_NODE_TARBALL}" \
    && echo "${_NODE_SHA256}  /tmp/${_NODE_TARBALL}" | sha256sum -c - \
    && tar -xJf "/tmp/${_NODE_TARBALL}" -C /usr/local --strip-components=1 --no-same-owner \
         --exclude CHANGELOG.md --exclude LICENSE --exclude README.md \
    && rm "/tmp/${_NODE_TARBALL}" \
    && node --version && npm --version

# aws-cli v2: tasks run on AWS with a task role (e.g. `aws codeartifact login` for
# npm/pip); it uses the ECS container credentials endpoint, no keys in the image. AWS's
# installer zip bundles its own Python, separate from pyenv's. The zip's detached
# signature is checked against aws-cli-team.asc (copied from AWS's install guide; the
# fingerprint is asserted, so a swapped key file fails the build). The fingerprint on
# the `grep -q` line below is its only copy in this file. The weekly pin-bump job
# (scripts/bump_pins.py, aws-cli-key) compares the file with the install guide, refreshes
# it, rewrites that line when AWS rotates the key, and warns as expiry approaches.
ARG AWS_CLI_VERSION=2.39.3
COPY aws-cli-team.asc /tmp/aws-cli-team.asc
RUN case "${TARGETARCH}" in \
         amd64) _AWS_ARCH=x86_64 ;; \
         arm64) _AWS_ARCH=aarch64 ;; \
         *) echo "unsupported TARGETARCH for the AWS CLI: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && _AWS_DIR="$(mktemp -d)" \
    && export GNUPGHOME="${_AWS_DIR}/gnupg" && mkdir -m 700 "${GNUPGHOME}" \
    && gpg --batch --import /tmp/aws-cli-team.asc \
    && gpg --batch --fingerprint aws-cli@amazon.com | grep -q "FB5D B77F D5C1 18B8 0511  ADA8 A631 0ACC 4672 475C" \
    && _AWS_ZIP="awscli-exe-linux-${_AWS_ARCH}-${AWS_CLI_VERSION}.zip" \
    && curl -fsSL --retry 3 -o "${_AWS_DIR}/awscliv2.zip" "https://awscli.amazonaws.com/${_AWS_ZIP}" \
    && curl -fsSLo "${_AWS_DIR}/awscliv2.zip.sig" "https://awscli.amazonaws.com/${_AWS_ZIP}.sig" \
    && gpg --batch --verify "${_AWS_DIR}/awscliv2.zip.sig" "${_AWS_DIR}/awscliv2.zip" \
    && unzip -q "${_AWS_DIR}/awscliv2.zip" -d "${_AWS_DIR}" \
    && "${_AWS_DIR}/aws/install" --install-dir /usr/local/aws-cli --bin-dir /usr/local/bin \
    && rm -rf "${_AWS_DIR}" /tmp/aws-cli-team.asc \
    && aws --version

# uv: Astral's static binaries from their image, pinned by tag and digest (static, so
# they run on glibc and musl alike).
COPY --from=ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 /uv /uvx /usr/local/bin/

ENV PYENV_ROOT=/usr/local/pyenv
ENV PATH="${PYENV_ROOT}/bin:${PYENV_ROOT}/shims:${PATH}"

# pyenv.run itself just curls bin/pyenv-installer from pyenv-installer's unversioned
# master branch with no checksum -- fetch that script directly, pinned to a specific
# commit, with a checksum we computed ourselves (TOFU; pyenv-installer publishes none).
RUN curl -fsSL "https://raw.githubusercontent.com/pyenv/pyenv-installer/bdd89156f0e591558ca901c5984387dd993157f9/bin/pyenv-installer" -o /tmp/pyenv-installer.sh \
    && echo "2bf587665219d2ed3e262fc2c3d9e6843b48f64435bc489d936f03e68b5f610d  /tmp/pyenv-installer.sh" | sha256sum -c \
    && bash /tmp/pyenv-installer.sh \
    && rm /tmp/pyenv-installer.sh \
    && pyenv install 3.12 \
    && pyenv global 3.12

# Anthropic's own installer, not npm -- same reasoning and fix as
# images/warren-docker-dev-base/Dockerfile (e1e1941): npm's global install splits the
# CLI into a wrapper package plus a separately-fetched native-binary
# optionalDependency, installed by a postinstall script a container killed mid-fetch
# (e.g. by warren's idle reaper) can leave corrupted -- silently, since `npm install`
# itself had already exited 0 by then. This installer fetches one checksum-verified
# binary directly (its platform detection picks the glibc build on Debian), no
# postinstall step to interrupt. It installs under $HOME (root's at build time); the
# verified binary is then copied to /usr/local/bin (R26/S12 (c) below).
#
# R26/S12: install.sh itself is still TOFU-only (Anthropic publishes no checksum for
# the script to pin against -- unlike pyenv-installer above, where we computed our own
# TOFU hash; a dynamic, frequently-updated install script isn't a good fit for that same
# pinning, and claude.ai/install.sh's content isn't advertised as stable/pinnable the
# way a specific git commit's raw file is). That gap is left as-is, deliberately
# unresolved, per this audit's existing broader tracking of curl|bash TOFU installers.
#
# What IS verifiable, and wasn't being checked at all before this: Anthropic publishes
# a GPG-signed manifest.json (signing key fingerprint
# 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE, security@anthropic.com) with a SHA256
# checksum per platform binary for every release from 2.1.89 onward
# (https://code.claude.com/docs/en/setup#binary-integrity-and-code-signing). After
# install.sh runs, verify the signature on that manifest and that the installed
# binary's own checksum matches the manifest's entry for this image's actual
# architecture (linux-{arm64,x64}, the glibc builds; the -musl ones were 1.2's) --
# catching a tampered or corrupted binary even though the script that fetched it was
# still TOFU.
# R26/S12 (c): the installer writes the binary under $HOME, /root at build time. The
# workspace runs as warren (uid 1000; ecs-base's entrypoint drops to it), which can't
# enter the 0700 /root, so a /usr/local/bin/claude symlink into /root (what 1.3.0 had
# before this) gave the workspace user "command not found". The verified binary is
# installed as a root-owned file in /usr/local/bin instead, and the installer's copy
# and state under /root are removed.
ARG CLAUDE_CODE_VERSION=2.1.309
RUN curl -fsSL https://claude.ai/install.sh | bash -s ${CLAUDE_CODE_VERSION} \
    && case "${TARGETARCH}" in \
         amd64) _CC_PLATFORM=linux-x64 ;; \
         arm64) _CC_PLATFORM=linux-arm64 ;; \
         *) echo "unsupported TARGETARCH for Claude Code manifest verification: ${TARGETARCH}" >&2; exit 1 ;; \
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
    && _CC_ACTUAL="$(sha256sum "/root/.local/share/claude/versions/${CLAUDE_CODE_VERSION}" | cut -d' ' -f1)" \
    && if [ -z "${_CC_EXPECTED}" ] || [ "${_CC_EXPECTED}" = null ] || [ "${_CC_EXPECTED}" != "${_CC_ACTUAL}" ]; then \
         echo "Claude Code binary checksum mismatch for ${_CC_PLATFORM} ${CLAUDE_CODE_VERSION}: expected ${_CC_EXPECTED}, got ${_CC_ACTUAL}" >&2; \
         exit 1; \
       fi \
    && install -m 0755 "/root/.local/share/claude/versions/${CLAUDE_CODE_VERSION}" /usr/local/bin/claude \
    && [ "$(claude --version)" = "${CLAUDE_CODE_VERSION} (Claude Code)" ] \
    && rm -rf "${_CC_DIR}" /root/.local/bin/claude /root/.local/share/claude /root/.claude /root/.claude.json

# codex (github.com/openai/codex): the release's standalone binary, pinned by version and
# sha256, not npm (@openai/codex fetches the platform binary as an optionalDependency, the
# same split as Claude Code's npm package above). OpenAI publishes Linux builds for musl
# only; they are statically linked, so they run unchanged on glibc. The sha256s are the
# release assets' digests from GitHub's release API
# (`gh api repos/openai/codex/releases/tags/rust-v<version>`); the release's
# codex-package_SHA256SUMS covers only the larger codex-package-* bundles, not these
# assets. warren's codex profile, including its hook-trust hashes, was checked against
# this version (docs/harnesses.md), so a bump needs that check redone.
# /etc/codex/config.toml is codex's system config layer, read under the CODEX_HOME one
# warren generates: it turns off the update check at startup (codex has no env var for it).
ARG CODEX_VERSION=0.166.0
ARG CODEX_SHA256_AMD64=a0bf572d2f93f056c6712a6da348e96078dc84f3885fd7be67807ef389cb3978
ARG CODEX_SHA256_ARM64=94eb707605ec2646b2e05b7edf7c4e7b3ccf02b16237c34ae9beb8cfb7f810a9
RUN case "${TARGETARCH}" in \
         amd64) _CX_TRIPLE=x86_64-unknown-linux-musl; _CX_SHA256="${CODEX_SHA256_AMD64}" ;; \
         arm64) _CX_TRIPLE=aarch64-unknown-linux-musl; _CX_SHA256="${CODEX_SHA256_ARM64}" ;; \
         *) echo "unsupported TARGETARCH for codex: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && _CX_DIR="$(mktemp -d)" \
    && curl -fsSL --retry 3 -o "${_CX_DIR}/codex.tar.gz" \
         "https://github.com/openai/codex/releases/download/rust-v${CODEX_VERSION}/codex-${_CX_TRIPLE}.tar.gz" \
    && echo "${_CX_SHA256}  ${_CX_DIR}/codex.tar.gz" | sha256sum -c - \
    && tar -xzf "${_CX_DIR}/codex.tar.gz" -C "${_CX_DIR}" "codex-${_CX_TRIPLE}" \
    && install -m 0755 "${_CX_DIR}/codex-${_CX_TRIPLE}" /usr/local/bin/codex \
    && rm -rf "${_CX_DIR}" \
    && mkdir -p /etc/codex \
    && printf 'check_for_update_on_startup = false\n' > /etc/codex/config.toml \
    && [ "$(codex --version)" = "codex-cli ${CODEX_VERSION}" ] \
    && rm -rf /root/.codex

# pi (@earendil-works/pi-coding-agent, github.com/earendil-works/pi; it was
# @mariozechner/pi-coding-agent up to 0.73.1, now deprecated in favour of this name):
# npm ci from the package.json + package-lock.json in pi/ next to this file, into
# /opt/pi, so every transitive package is pinned by the lockfile's sha512 integrity
# hashes. --ignore-scripts: no install scripts run. No dependency needs one: the image
# codec and the code-mode sandbox are WebAssembly (photon-node, quickjs-wasi, both
# loaded below as a check), and pi-tui's prebuilt X11 clipboard addon is only loaded
# when DISPLAY is set (it needs libxcb, absent here; pi falls back without it). The
# lockfile is platform-independent (npm records every platform's optional packages).
# The version lives only in pi/package.json; after changing it, regenerate the lockfile
# (scripts/bump_pins.py does both; its docstring has the command to run by hand).
# `pi --version` prints to stderr. Needs Node >= 22.19.
COPY pi/package.json pi/package-lock.json /opt/pi/
RUN cd /opt/pi \
    && npm ci --ignore-scripts --omit=dev --no-audit --no-fund --cache /tmp/npm-cache \
    && rm -rf /tmp/npm-cache \
    && ln -s /opt/pi/node_modules/.bin/pi /usr/local/bin/pi \
    && _PI_VERSION="$(node -p 'require("/opt/pi/package.json").dependencies["@earendil-works/pi-coding-agent"]')" \
    && [ "$(pi --version 2>&1)" = "${_PI_VERSION}" ] \
    && node -e 'require("@silvia-odwyer/photon-node")' \
    && node --input-type=module -e 'await import("quickjs-wasi")'

# No self-updates: the harnesses are root-owned and pinned, so an update could only fail
# or drift from the pin; rebuild with new pins instead (scripts/bump_pins.py proposes
# them weekly). DISABLE_AUTOUPDATER: Claude Code's auto-updater. PI_SKIP_VERSION_CHECK:
# pi's startup check for a newer release (it only notifies; `pi update` is manual, and
# can't write the root-owned /opt/pi as the workspace user).
# codex: /etc/codex/config.toml above.
ENV DISABLE_AUTOUPDATER=1 \
    PI_SKIP_VERSION_CHECK=1

# Deliberately NOT here: anything agent-specific, or WARREN_APP_CMD wiring — purpose-built
# agent images (warren-ecs-agent-base and friends) are separate, layered on top of this
# tag instead. ecs-base's own idle-by-default entrypoint is untouched.

# Additional dev tools, commented out for now — uncomment individually as needed.
# Debian/apt equivalents of ../../../../images/warren-dev-base's candidate list; kept
# in sync with that file's comment block.
#
# RUN apt-get update && apt-get install -y --no-install-recommends \
#         vim nano less \
#         fzf bat tree yq \
#         httpie \
#         dnsutils iputils-ping \
#         zip \
#     && rm -rf /var/lib/apt/lists/*
#
# RUN npm install -g pnpm yarn typescript ts-node
#
# RUN pip install --upgrade pipx poetry
#
# # zsh is already in ecs-base; Oh My Zsh (devcontainers/images universal default shell)
# RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
#
# # SDKMAN! (Java/Kotlin/Scala/Groovy version manager — same per-project-version
# # rationale as pyenv above). Needs bash/zip/unzip, already present/available here.
# ENV SDKMAN_DIR=/usr/local/sdkman
# RUN curl -fsSL "https://get.sdkman.io" | bash
#
# # Go
# RUN apt-get update && apt-get install -y --no-install-recommends golang && rm -rf /var/lib/apt/lists/*
#
# # Rust
# RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
#
# # Docker CLI (for a workspace that itself talks to a mounted socket)
# RUN apt-get update && apt-get install -y --no-install-recommends docker.io && rm -rf /var/lib/apt/lists/*
#
# # Browser automation — Playwright's bundled browsers are glibc builds, so they work here.
# RUN npm install -g playwright && npx playwright install --with-deps chromium
