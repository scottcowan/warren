# warren-ecs-dev-base — convenience layer on top of ecs-base, NOT a fork of it (same
# pattern as ../../../../images/warren-dev-base, the Docker-env counterpart). Gets Claude
# Code plus common dev tools preinstalled, without touching ecs-base's own minimal,
# no-sshd design (see ../ecs-base/Dockerfile's header).
#
# Node comes from Alpine's own apk package, NOT nvm, unlike warren-dev-base: nvm installs
# nodejs.org's official prebuilt tarballs, which are glibc-linked — they don't run on
# musl (Alpine) without a compatibility shim (gcompat), and even then native addons in
# that combination aren't reliable. Alpine's own nodejs/npm packages are musl-native and
# current enough here (no NodeSource/nvm needed). Python DOES use pyenv here — pyenv
# compiles from source rather than downloading prebuilt binaries, so it's musl-safe the
# same way it's glibc-safe on warren-dev-base; it's just Node that's the Alpine exception.
#
# Trust boundary: Alpine's own apk repositories (community, for ripgrep/nodejs/npm),
# pyenv's install script (fetched over HTTPS from its official GitHub repo), and
# Anthropic's own native installer (`curl https://claude.ai/install.sh | bash`, pinned
# to an exact version — NOT the npm package `@anthropic-ai/claude-code`; see the Claude
# Code install RUN step below for why). The installed binary's own integrity is checked
# against Anthropic's GPG-signed release manifest (R26/S12) -- the install.sh *script*
# fetch itself remains TOFU-only (no published checksum for that script exists to pin
# against), a known, deliberately-unresolved broader supply-chain gap this audit
# already tracks separately.
FROM ghcr.io/scottcowan/warren-ecs-base:latest@sha256:c1b5c590fce9b127d94bb5632ddc7aeb0e7b0431a6bdd04fe3c54b89e4597912
# warren-ecs-base:latest (warren-ecs-base-v1.0.1, with the S1 build fix and
# UX-1's zsh banner/prompt) as of 2026-10-17

# ca-certificates/git already present from ecs-base.
# build-base + pyenv's documented build deps (musl-compatible, source compile).
# bash already present from ecs-base.
# gnupg: verifies Anthropic's signed release manifest for the Claude Code binary
# (R26/S12 below), not needed by anything else in this image.
RUN apk add --no-cache \
        curl jq gnupg ripgrep build-base nodejs npm \
        openssl-dev zlib-dev bzip2 bzip2-dev readline-dev sqlite-dev ncurses-dev \
        xz-dev tk-dev libxml2-dev xmlsec-dev libffi-dev

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
# binary directly (its platform detection explicitly covers musl/Alpine), no
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
# architecture (linux-{arm64,x64}-musl on Alpine) -- catching a tampered or corrupted
# binary even though the script that fetched it was still TOFU.
# R26/S12 (c): the installer's own $HOME/.local/bin/claude symlink target above
# hardcodes /root -- this image has no USER directive anywhere in its lineage (checked:
# none in ecs-base, ecs-dev-base, or ecs-agent-base), so $HOME is /root and this is
# correct today. It is a landmine for later, though: if a non-root USER is ever added
# to this image (or a layer built on top of it), this symlink -- and the manifest
# verification step's /root/.local/share/claude/versions/... path below -- would both
# silently point at the wrong (root's, now-unreadable-by-the-new-user) home directory
# instead of failing loudly. Not fixed now since there's no USER directive to break
# against yet; flagging so whoever adds one first fixes this too.
ARG CLAUDE_CODE_VERSION=2.1.301
RUN curl -fsSL https://claude.ai/install.sh | bash -s ${CLAUDE_CODE_VERSION} \
    && ln -sf /root/.local/bin/claude /usr/local/bin/claude \
    && case "$(uname -m)" in \
         x86_64) _CC_ARCH=x64 ;; \
         aarch64) _CC_ARCH=arm64 ;; \
         *) echo "unsupported arch for Claude Code manifest verification: $(uname -m)" >&2; exit 1 ;; \
       esac \
    && _CC_PLATFORM="linux-${_CC_ARCH}-musl" \
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
    && if [ "${_CC_EXPECTED}" != "${_CC_ACTUAL}" ]; then \
         echo "Claude Code binary checksum mismatch for ${_CC_PLATFORM} ${CLAUDE_CODE_VERSION}: expected ${_CC_EXPECTED}, got ${_CC_ACTUAL}" >&2; \
         exit 1; \
       fi \
    && rm -rf "${_CC_DIR}"

# Deliberately NOT here: anything agent-specific, or WARREN_APP_CMD wiring — purpose-built
# agent images (warren-ecs-agent-base and friends) are separate, layered on top of this
# tag instead. ecs-base's own idle-by-default entrypoint is untouched.

# Additional dev tools, commented out for now — uncomment individually as needed.
# Alpine/apk equivalents of ../../../../images/warren-dev-base's candidate list; kept
# in sync with that file's comment block.
#
# RUN apk add --no-cache \
#         vim nano less \
#         fzf bat eza zoxide tree jq yq \
#         httpie \
#         bind-tools iputils \
#         zip unzip \
#         github-cli
#
# RUN npm install -g pnpm yarn typescript ts-node
#
# RUN pip install --upgrade pipx poetry
#
# # zsh + Oh My Zsh (devcontainers/images universal default shell)
# RUN apk add --no-cache zsh \
#     && sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
#
# # SDKMAN! (Java/Kotlin/Scala/Groovy version manager — same per-project-version
# # rationale as pyenv above). Needs bash/zip/unzip, already present/available here.
# ENV SDKMAN_DIR=/usr/local/sdkman
# RUN curl -fsSL "https://get.sdkman.io" | bash
#
# # Go
# RUN apk add --no-cache go
#
# # Rust (musl target)
# RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
#
# # Docker CLI (for a workspace that itself talks to a mounted socket)
# RUN apk add --no-cache docker-cli
#
# # Browser automation — see this file's header note: Playwright's bundled browser
# # binaries have the same glibc/musl issue as Node did; untested on this image.
# RUN npm install -g playwright && npx playwright install --with-deps chromium
