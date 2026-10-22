#!/bin/sh
set -e

ssh-keygen -A

[ -f /etc/warren/authorized_keys ] || touch /etc/warren/authorized_keys
chmod 0644 /etc/warren/authorized_keys

exec /usr/sbin/sshd -D -e "$@"
