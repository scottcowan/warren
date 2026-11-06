# warren-docker-dev-base — convenience layer on top of warren-docker-base (D-10 sibling
# pattern), NOT a fork of it. Projects that don't need D-09's arbitrary-Containerfile
# escape hatch can use this tag directly as their docker_image and get Claude Code plus
# common dev tools preinstalled, for the common case: a local Podman/Docker daemon
# reached by direct exec (warren-docker-base itself carries no sshd — see
# images/warren-docker-base/Dockerfile for why sshd is the exception, not the default).
#
# Node and Python come from nvm/pyenv, not apt — a fixed system nodejs/python3 package
# locks every workspace built from this tag to one version; a version manager lets a
# workspace pick per-project, same as a real dev machine.
#
# Trust boundary (RESEARCH.md "Package Legitimacy Audit" / T-04-04-SC): this layer's own
# external inputs are the Debian apt repositories, nvm's and pyenv's own install scripts
# (both fetched over HTTPS from their official GitHub repos, the standard documented
# install path for each), and the npm registry for the Claude Code CLI itself
# (`@anthropic-ai/claude-code`, the official first-party Anthropic package, pinned to a
# major version so an unreviewed CLI upgrade can't silently change agent behavior inside
# every future workspace built from this tag), and opencode's GitHub release tarball
# (version and sha256 pinned below). The plain warren-docker-base remains
# available and untouched for anyone who prefers to decline this layer's supply-chain
# surface.
FROM ghcr.io/scottcowan/warren-docker-base:latest@sha256:6102cea6f4a8a3668bd14c8aa87d14238b97e132b7efdb5960341107667e6990
# warren-docker-base:latest (warren-docker-base-v1.0.1, with the S1 build fix
# and UX-1's zsh banner/prompt) as of 2026-10-17

# git/curl/jq/tmux already present from warren-docker-base.
# ripgrep: common dev tool. build-essential + pyenv's documented build deps: pyenv
# compiles Python from source, so these aren't optional even though they look like
# they're only needed for native extensions.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ripgrep build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev \
        libsqlite3-dev libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev \
        libffi-dev liblzma-dev \
    && rm -rf /var/lib/apt/lists/*

ENV NVM_DIR=/usr/local/nvm
ENV PYENV_ROOT=/usr/local/pyenv
ENV PATH="${PYENV_ROOT}/bin:${PYENV_ROOT}/shims:${PATH}"

# Checksum pinned ourselves (TOFU) against this exact tagged commit -- nvm-sh does not
# publish an official sha256 for install.sh, but pinning the hash we fetched still
# catches any tampering of the tag/CDN between here and a future image rebuild.
RUN mkdir -p "$NVM_DIR" \
    && curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh -o /tmp/nvm-install.sh \
    && echo "abdb525ee9f5b48b34d8ed9fc67c6013fb0f659712e401ecd88ab989b3af8f53  /tmp/nvm-install.sh" | sha256sum -c \
    && bash /tmp/nvm-install.sh \
    && rm /tmp/nvm-install.sh \
    && . "$NVM_DIR/nvm.sh" \
    && nvm install --lts \
    && nvm alias default 'lts/*' \
    && ln -sf "$NVM_DIR/versions/node/$(nvm version default)/bin/node" /usr/local/bin/node \
    && ln -sf "$NVM_DIR/versions/node/$(nvm version default)/bin/npm" /usr/local/bin/npm \
    && ln -sf "$NVM_DIR/versions/node/$(nvm version default)/bin/npx" /usr/local/bin/npx

# pyenv.run itself just curls bin/pyenv-installer from pyenv-installer's unversioned
# master branch with no checksum -- fetch that script directly, pinned to a specific
# commit, with a checksum we computed ourselves (TOFU; pyenv-installer publishes none).
RUN curl -fsSL "https://raw.githubusercontent.com/pyenv/pyenv-installer/bdd89156f0e591558ca901c5984387dd993157f9/bin/pyenv-installer" -o /tmp/pyenv-installer.sh \
    && echo "2bf587665219d2ed3e262fc2c3d9e6843b48f64435bc489d936f03e68b5f610d  /tmp/pyenv-installer.sh" | sha256sum -c \
    && bash /tmp/pyenv-installer.sh \
    && rm /tmp/pyenv-installer.sh \
    && pyenv install 3.12 \
    && pyenv global 3.12

# Pinned to an exact version, not floating on `latest`/`stable` -- an
# unreviewed CLI upgrade shouldn't silently change agent behavior inside
# every future workspace built from this tag.
#
# Anthropic's own installer (not npm): npm's global install split the CLI
# into a wrapper package plus a separately-fetched native-binary
# optionalDependency, installed by a postinstall script. A container killed
# (e.g. by warren's idle reaper) while that postinstall was mid-fetch left a
# truncated native binary and a dangling bin symlink behind -- silently,
# since the npm install step itself had already exited 0 by then. This
# installer fetches one checksum-verified binary directly, no postinstall
# step to interrupt.
#
# Installs to $HOME/.local/bin (root's, since this image runs as root) --
# symlinked into /usr/local/bin so it's on PATH the same way node/npm/npx are.
RUN curl -fsSL https://claude.ai/install.sh | bash -s 2.1.309 \
    && ln -sf /root/.local/bin/claude /usr/local/bin/claude

# opencode (github.com/anomalyco/opencode): the release's single static-ish binary,
# pinned by version and sha256, not npm (whose opencode-ai package fetches the binary
# in a postinstall script, the same failure mode as Claude Code's npm package above).
# The glibc builds, matching this image's Debian base (python:3.11-slim); the -musl
# assets are for Alpine. The sha256s are the release assets' digests from GitHub's
# release API (`gh api repos/anomalyco/opencode/releases/tags/v1.19.5`). warren's
# opencode profile was checked against this version (docs/harnesses.md).
ARG TARGETARCH
ARG OPENCODE_VERSION=1.19.5
ARG OPENCODE_SHA256_AMD64=588310a336fa3b9df36b3f0225b26f679d453efaad0cf3d66c3651ef3ec1647a
ARG OPENCODE_SHA256_ARM64=fae5be262d693b7c5e562856cc473e59e741772936db0c0600ac0d5ed5bd088b
RUN case "${TARGETARCH}" in \
         amd64) _OC_ARCH=x64; _OC_SHA256="${OPENCODE_SHA256_AMD64}" ;; \
         arm64) _OC_ARCH=arm64; _OC_SHA256="${OPENCODE_SHA256_ARM64}" ;; \
         *) echo "unsupported TARGETARCH for opencode: ${TARGETARCH}" >&2; exit 1 ;; \
       esac \
    && _OC_DIR="$(mktemp -d)" \
    && curl -fsSL --retry 3 -o "${_OC_DIR}/opencode.tar.gz" \
         "https://github.com/anomalyco/opencode/releases/download/v${OPENCODE_VERSION}/opencode-linux-${_OC_ARCH}.tar.gz" \
    && echo "${_OC_SHA256}  ${_OC_DIR}/opencode.tar.gz" | sha256sum -c - \
    && tar -xzf "${_OC_DIR}/opencode.tar.gz" -C "${_OC_DIR}" opencode \
    && install -m 0755 "${_OC_DIR}/opencode" /usr/local/bin/opencode \
    && rm -rf "${_OC_DIR}" \
    && [ "$(opencode --version)" = "${OPENCODE_VERSION}" ]

# Deliberately NOT here: anything agent-specific — purpose-built agent images
# (warren-agent-base and friends) are separate, layered on top of this tag instead.
# This is dev tooling for an interactive session only.

# Additional dev tools, commented out for now — uncomment individually as needed.
# Kept here rather than in a separate file so the full candidate list stays visible
# next to what's already installed above.
#
# RUN apt-get update \
#     && apt-get install -y --no-install-recommends \
#         # CLI/editor niceties
#         vim nano less man-db \
#         fzf bat eza zoxide tree jq yq \
#         httpie \
#         # network/debug
#         dnsutils iputils-ping netcat-openbsd traceroute \
#         # version control extras
#         gh \
#         # compression
#         zip unzip \
#     && rm -rf /var/lib/apt/lists/*
#
# RUN npm install -g pnpm yarn typescript ts-node
#
# RUN pip install --upgrade pipx poetry
#
# # zsh + Oh My Zsh (devcontainers/images universal default shell)
# RUN apt-get update && apt-get install -y --no-install-recommends zsh \
#     && rm -rf /var/lib/apt/lists/* \
#     && sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
#
# # SDKMAN! (Java/Kotlin/Scala/Groovy version manager — same per-project-version
# # rationale as nvm/pyenv above)
# ENV SDKMAN_DIR=/usr/local/sdkman
# RUN curl -fsSL "https://get.sdkman.io" | bash
#
# # Go
# ENV GOPATH=/usr/local/go-path
# RUN curl -fsSL https://go.dev/dl/go1.23.0.linux-amd64.tar.gz | tar -C /usr/local -xz \
#     && ln -sf /usr/local/go/bin/go /usr/local/bin/go
#
# # Rust
# RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
#
# # Docker CLI (for a workspace that itself talks to a mounted socket)
# RUN curl -fsSL https://get.docker.com | sh
#
# # Browser automation (see warren-docker-dev-base header note re: Playwright on glibc vs musl —
# # still an open question whether this belongs here, per-project, or on its own layer)
# RUN npm install -g playwright && npx playwright install --with-deps chromium
