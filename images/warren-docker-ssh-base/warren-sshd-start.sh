#!/bin/sh
# warren-docker-ssh-base entrypoint (docs/workspace-ssh.md): start sshd, then hand over to
# warren-docker-base's own entrypoint, unchanged.
#
# - Host key: one ed25519 key, generated at the container's first start under
#   /etc/ssh/warren (root, 0700). None is baked into the image. It survives the
#   container's stop/start; a re-provisioned container gets a new one.
# - /etc/warren/authorized_keys: created empty (root, 0644) if the server hasn't written
#   it yet. PodmanRuntime writes the key POST /workspaces/{id}/connect mints there, into
#   the running container, and empties it again on stop/destroy.
# - sshd runs in the background with a minimal environment, so the workspace's secrets
#   (in this container's environment) are not in sshd's or its sessions'.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
set -e

if [ "$(id -u)" = 0 ]; then
    umask 077
    mkdir -p /run/sshd /etc/ssh/warren
    chmod 0755 /run/sshd
    chmod 0700 /etc/ssh/warren
    key=/etc/ssh/warren/ssh_host_ed25519_key
    if [ ! -s "$key" ] || ! ssh-keygen -l -f "$key" >/dev/null 2>&1; then
        rm -f "$key" "$key.pub"
        ssh-keygen -q -t ed25519 -N '' -C "warren-workspace-${WARREN_WORKSPACE_ID:-unknown}" -f "$key"
        echo "warren-sshd: generated host key" >&2
    fi
    chmod 0644 "$key.pub"
    echo "warren-sshd: host key $(ssh-keygen -l -f "$key.pub")" >&2
    mkdir -p /etc/warren
    chmod 0755 /etc/warren
    [ -e /etc/warren/authorized_keys ] || : > /etc/warren/authorized_keys
    chown 0:0 /etc/warren/authorized_keys
    chmod 0644 /etc/warren/authorized_keys
    env -i PATH="$PATH" LANG=C.UTF-8 /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config </dev/null &
else
    echo "warren-sshd: not root, sshd not started" >&2
fi

exec /usr/local/bin/python3.11 /entrypoint.py "$@"
