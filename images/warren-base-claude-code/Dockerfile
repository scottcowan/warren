ARG BASE_IMAGE=ghcr.io/scottcowan/warren-docker-base:latest@sha256:7ba55669f50253fa1ddb7aa5992d21c8df05f935836fe54212282561add66a95
# warren-docker-base:latest (warren-docker-base-v1.0.1, with the S1 build fix
# and UX-1's zsh banner/prompt) as of 2026-10-17
FROM ${BASE_IMAGE}

# Node 20 LTS (Ubuntu apt ships 12.x which is too old for Claude Code).
# NodeSource doesn't publish an official checksum for this script and it's
# regenerated routinely (not pinned to a tag/commit like nvm/pyenv below), so the
# checksum here is TOFU against the content as fetched on 2026-10-17, not a
# vendor-published value -- it still catches tampering between here and a future bump.
RUN curl -fsSL https://deb.nodesource.com/setup_20.x -o /tmp/nodesource-setup.sh \
    && echo "2c4c6683a17b6f4128898a7b521e3c8bb725a99ffaf1b5e32ac97c6fa7d381be  /tmp/nodesource-setup.sh" | sha256sum -c \
    && bash /tmp/nodesource-setup.sh \
    && rm /tmp/nodesource-setup.sh \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Pinned version -- see images/warren-docker-dev-base/Dockerfile's rationale for
# pinning this CLI; this image predates that fix and still installs it via npm
# rather than Anthropic's installer script.
#
# warren doesn't build/publish this image (no CI workflow, not in `warren
# doctor`'s canonical list) -- it's offered as a Dockerfile for you to build
# and tag yourself. See README.md in this directory.
RUN npm install -g @anthropic-ai/claude-code@2.1.308

WORKDIR /workspace

CMD ["claude"]
