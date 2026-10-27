#!/bin/sh
# Interactive entry point for `warren connect` over ECS Exec (AH7/AG4.1).
# Usage: warren-session <shell> [<harness>|-] [new|-]. Attaches to the persistent "main"
# tmux session, creating it with the warren shell (AG2a), so a dropped SSM connection
# leaves the user's harness running. --harness/--new open a window in a live session. ECS Exec sessions start as root regardless
# of the container's USER, so drop to the workspace user (AD3) first. Nothing here may
# resolve through the task's PATH or read workspace-controlled files while still root.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset ENV BASH_ENV
set -e

case "${1:-bash}" in
    bash) shell=/bin/bash ;;
    zsh) shell=/bin/zsh ;;
    sh) shell=/bin/sh ;;
    *) echo "warren-session: unsupported shell: $1" >&2; exit 2 ;;
esac
harness=${2:--}
case "$harness" in
    -) ;;
    *[!a-z0-9-]*|-*) echo "warren-session: invalid harness: $harness" >&2; exit 2 ;;
esac
new=${3:--}

if [ "$(/usr/bin/id -u)" = 0 ]; then
    if ! /usr/bin/id warren >/dev/null 2>&1; then
        echo "warren-session: no warren user in this image - refusing to open a root shell" >&2
        exit 1
    fi
    # The workspace's secrets, as the entrypoint received them (root-only copy in the
    # container's own filesystem, not the volume): ECS Exec doesn't carry PID 1's env.
    . /usr/local/lib/warren/secrets.sh
    warren_secrets_load /run/warren/secrets.env
    HOME=/home/warren
    export HOME
    exec /sbin/su-exec warren:warren /usr/local/bin/warren-session "$@"
fi
# Now uid 1000. AH1: start in the git checkout when entrypoint.sh linked /workspace to it.
if [ -L /workspace ]; then
    cd /workspace 2>/dev/null || cd "$HOME" 2>/dev/null || true
else
    cd "$HOME" 2>/dev/null || true
fi
set -- -e WARREN_CONNECT=1
[ "$harness" = - ] || set -- "$@" -e "WARREN_CONNECT_HARNESS=$harness"
[ "$new" != new ] || set -- "$@" -e WARREN_CONNECT_NEW=1
if { [ "$harness" != - ] || [ "$new" = new ]; } && /usr/bin/tmux has-session -t main 2>/dev/null; then
    exec /usr/bin/tmux new-window -t main "$@" "$shell" \; attach-session -t main
fi
exec /usr/bin/tmux new-session -A -s main "$@" "$shell"
