#!/bin/sh
# warren-ecs-ssh-base entrypoint wrapper (docs/ecs-ssh.md). Installed at
# /usr/local/bin/entrypoint.sh; ecs-base's own entrypoint moves to
# /usr/local/lib/warren/ecs-entrypoint.sh and is otherwise unchanged.
#
# ecs-base's entrypoint starts as root, loads the workspace secrets, drops to warren and
# re-execs /usr/local/bin/entrypoint.sh, i.e. this wrapper, as uid 1000 with the secrets
# in its environment. That second call is the only one that starts sshd (warren-sshd,
# in the background, as uid 1000), then the base entrypoint carries on to the workload
# exactly as in ecs-base. As root this wrapper does nothing but hand over.
#
# A task started as non-root (WARREN_ECS_TASK_USER) calls this once, as uid 1000,
# before the base entrypoint has loaded the secrets: sshd still starts, but only a
# key in the template's plain env reaches it.
set -e
if [ "$(/usr/bin/id -u)" != 0 ]; then
    /usr/local/bin/warren-sshd </dev/null &
fi
exec /usr/local/lib/warren/ecs-entrypoint.sh "$@"
