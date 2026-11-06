# syntax=docker/dockerfile:1.7
# warren-ecs-dev-base — convenience layer on top of ecs-base, NOT a fork of it (same
# pattern as ../../../../images/warren-dev-base, the Docker-env counterpart). Gets Claude
# Code plus common dev tools preinstalled, without touching ecs-base's own minimal,
# no-sshd design (see ../ecs-base/Dockerfile's header).
#
# Debian bookworm (glibc) since 1.3.0, because warren-ecs-base 1.5.0 is; 1.2 and earlier were Alpine.
# Packages come from apt. Node is nodejs.org's official linux tarball (glibc-linked, so
# prebuilt npm native addons load), the AWS CLI is AWS's official v2 installer (Debian's
# `awscli` package is v1), Python is pyenv-compiled, and Claude Code is the glibc build.
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
# already tracks separately.
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
# postinstall step to interrupt. Installs to $HOME/.local/bin (root's, this image runs
# as root); symlinked into /usr/local/bin so it's on PATH the same way node/npm are.
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
# R26/S12 (c): the installer's own $HOME/.local/bin/claude symlink target above
# hardcodes /root -- this image has no USER directive anywhere in its lineage (checked:
# none in ecs-base, ecs-dev-base, or ecs-agent-base), so $HOME is /root and this is
# correct today. It is a landmine for later, though: if a non-root USER is ever added
# to this image (or a layer built on top of it), this symlink -- and the manifest
# verification step's /root/.local/share/claude/versions/... path below -- would both
# silently point at the wrong (root's, now-unreadable-by-the-new-user) home directory
# instead of failing loudly. Not fixed now since there's no USER directive to break
# against yet; flagging so whoever adds one first fixes this too.
ARG CLAUDE_CODE_VERSION=2.1.309
RUN curl -fsSL https://claude.ai/install.sh | bash -s ${CLAUDE_CODE_VERSION} \
    && ln -sf /root/.local/bin/claude /usr/local/bin/claude \
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
    && rm -rf "${_CC_DIR}"

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
