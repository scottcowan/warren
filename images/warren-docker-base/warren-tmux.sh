#!/bin/sh
# warren-docker-base: `tmux` for sessions that start as container root.
#
# The workload (tmux server, harnesses, app) runs as `warren` (uid 1000) once the
# entrypoint has dropped privileges (entrypoint.py, root_phase), which writes
# /etc/warren/workload. `podman exec` and `docker exec` start as the image's USER (root),
# and a root tmux client would look in /tmp/tmux-0 and find no server, or start a second,
# root-owned one. So when root and that file exists, run tmux as the workload user.
# Otherwise (the workload runs as root, or this is the workload user) it is plain tmux.
if [ "$(id -u)" = 0 ] && [ -r /etc/warren/workload ]; then
    read -r uid gid home name < /etc/warren/workload
    case "$uid$gid" in
        ''|*[!0-9]*) ;;
        *)
            exec /usr/bin/setpriv --reuid="$uid" --regid="$gid" --init-groups \
                /usr/bin/env HOME="$home" USER="$name" LOGNAME="$name" /usr/bin/tmux "$@"
            ;;
    esac
fi
exec /usr/bin/tmux "$@"
