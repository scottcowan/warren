# syntax=docker/dockerfile:1.7
# warren-docker-ssh-base — opt-in layer on top of warren-docker-dev-base that adds an
# sshd for editor remoting (VS Code Remote-SSH, Cursor, JetBrains Gateway) into
# podman/docker-server workspaces. Published as ghcr.io/scottcowan/warren-docker-ssh-base.
# The podman counterpart of packages/warren-server/images/warren-ecs-ssh-base; see
# docs/workspace-ssh.md.
#
# warren-docker-base deliberately carries no sshd. This image adds one that matches what
# warren-server's podman runtime already does for SSH access
# (tests/integration/fixtures/ssh_test_image is the reference it was built against):
#   - container port 22, which PodmanRuntime publishes on the server host's 127.0.0.1
#     only when the operator sets WARREN_SSH_ACCESS_ENABLED=true;
#   - keys from /etc/warren/authorized_keys, which the server writes with the key it
#     mints per `POST /workspaces/{id}/connect` (one key at a time);
#   - users warren and warren-shell, the names the server returns.
# sshd_config carries the same hardening as warren-ecs-ssh-base: key-only, no root login,
# only those two users, local TCP forwarding only, no X11/agent forwarding. No host key
# in the image: one is generated at the container's first start.
#
# Pinned by digest like warren-docker-dev-base pins warren-docker-base:
# warren-docker-dev-base 1.1.0 (multi-arch), the first release with codex and pi, as of 2026-11-09.
FROM ghcr.io/scottcowan/warren-docker-dev-base:1.1.0@sha256:33be0122920dc1956fa5d655ebcc5df4803e4b704a75d28b22db28ec953168ca

# openssh-server from Debian's archive. Its postinst host keys are deleted (no image, and
# so no two workspaces, share a host key), the default sshd_config is replaced and the
# drop-in directory emptied.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/ssh/ssh_host_* \
    && rm -rf /etc/ssh/sshd_config.d \
    && mkdir -m 0755 /etc/ssh/sshd_config.d

# The two login users. `*`, not a locked `!` password: with UsePAM no, sshd refuses
# accounts whose password is locked even for key logins. `*` matches no password.
RUN useradd -m -s /bin/bash -u 1000 warren \
    && useradd -m -s /bin/bash -u 1001 warren-shell \
    && usermod -p '*' warren \
    && usermod -p '*' warren-shell \
    && mkdir -p /etc/warren \
    && chown 0:0 /etc/warren \
    && chmod 0755 /etc/warren

COPY --chown=0:0 --chmod=0644 sshd_config /etc/ssh/sshd_config
COPY --chown=0:0 --chmod=0755 warren-sshd-start.sh /usr/local/bin/warren-sshd-start

# SSH logins get a clean login environment, and Debian's /etc/profile resets PATH, so
# put the image's own PATH (pyenv shims) back for them.
RUN printf 'PATH="%s"\nexport PATH\n' "${PATH}" > /etc/profile.d/warren-path.sh \
    && chmod 0644 /etc/profile.d/warren-path.sh

# The config parses, with a throwaway host key.
RUN mkdir -p /run/sshd && ssh-keygen -q -t ed25519 -N '' -f /tmp/k \
    && /usr/sbin/sshd -t -f /etc/ssh/sshd_config -h /tmp/k \
    && rm -f /tmp/k /tmp/k.pub

# Starts sshd, then execs warren-docker-base's entrypoint (/entrypoint.py) unchanged.
ENTRYPOINT ["/usr/local/bin/warren-sshd-start"]
