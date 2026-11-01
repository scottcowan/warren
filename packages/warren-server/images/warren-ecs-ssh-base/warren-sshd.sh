#!/bin/sh
# warren-sshd: start the workspace's sshd (warren-ecs-ssh-base, docs/workspace-ssh.md).
#
# Runs as the workspace user (uid 1000), never root: entrypoint.sh (this image's
# wrapper) calls it after ecs-base's entrypoint has loaded the secrets and dropped
# privileges. sshd therefore has exactly the workload's privileges, and everything it
# reads (host key, authorized_keys) is the workspace user's own.
#
# 1. Host key: one ed25519 key, generated on first start under
#    /var/lib/warren/.warren-ssh on the workspace volume (EFS or EBS), so it survives
#    task restarts and the client's known_hosts entry (HostKeyAlias) stays valid.
# 2. authorized_keys: ~/.ssh/authorized_keys is rewritten from $SSH_AUTHORIZED_KEYS
#    (one or more public key lines) on every start, so removing a key from the secret
#    or template env revokes it at the next restart. Unset: any existing file is kept.
# 3. sshd runs in the foreground of this (backgrounded) process with a minimal
#    environment, so the workspace secrets in the entrypoint's environment are not
#    in sshd's.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
set -eu

if [ "$(id -u)" = 0 ]; then
    echo "warren-sshd: refusing to run as root; sshd runs as the workspace user" >&2
    exit 1
fi

umask 077
keydir=/var/lib/warren/.warren-ssh
key=$keydir/ssh_host_ed25519_key
home=$(getent passwd "$(id -u)" | cut -d: -f6)
[ -n "$home" ] || { echo "warren-sshd: no home directory for uid $(id -u)" >&2; exit 1; }

# A link or non-directory here is not ours: move it aside rather than follow it.
if [ -L "$keydir" ] || { [ -e "$keydir" ] && [ ! -d "$keydir" ]; }; then
    mv -f "$keydir" "$keydir.invalid.$$"
fi
mkdir -p "$keydir"
chmod 00700 "$keydir"
if [ -L "$key" ] || [ ! -s "$key" ] || ! ssh-keygen -l -f "$key" >/dev/null 2>&1; then
    rm -f "$key" "$key.pub"
    ssh-keygen -q -t ed25519 -N '' -C "warren-workspace-${WARREN_WORKSPACE_ID:-unknown}" -f "$key"
    echo "warren-sshd: generated host key" >&2
fi
chmod 0600 "$key"
echo "warren-sshd: host key $(ssh-keygen -l -f "$key.pub" 2>/dev/null || ssh-keygen -l -f "$key")" >&2

mkdir -p "$home/.ssh"
chmod 00700 "$home/.ssh"
if [ -n "${SSH_AUTHORIZED_KEYS:-}" ]; then
    tmp=$(mktemp "$home/.ssh/authorized_keys.XXXXXX")
    printf '%s\n' "$SSH_AUTHORIZED_KEYS" | tr -d '\r' > "$tmp"
    if ! ssh-keygen -l -f "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"
        echo "warren-sshd: SSH_AUTHORIZED_KEYS holds no valid public key; authorized_keys left unchanged" >&2
    else
        chmod 0600 "$tmp"
        mv -f "$tmp" "$home/.ssh/authorized_keys"
        ssh-keygen -l -f "$home/.ssh/authorized_keys" 2>/dev/null | sed 's/^/warren-sshd: authorized key /' >&2 || true
    fi
elif [ ! -s "$home/.ssh/authorized_keys" ]; then
    echo "warren-sshd: no SSH_AUTHORIZED_KEYS and no ~/.ssh/authorized_keys; nobody can log in yet" >&2
fi

exec env -i PATH="$PATH" HOME="$home" LANG=C.UTF-8 /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
