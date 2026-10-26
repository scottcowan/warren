#!/bin/sh
set -e

# Secrets arrive as a file the control plane wrote onto this workspace's volume just
# before RunTask (runtime/ecs_secrets.py). Export them, keep a root-only copy for ECS
# Exec sessions (warren-session) when root, and delete the file, all before anything
# workspace-controlled runs. git-init's clone credentials are never loaded here; its
# file is normally gone already and is deleted unread in case it isn't.
. /usr/local/lib/warren/secrets.sh
if [ "$(/usr/bin/id -u)" = 0 ]; then
    warren_secrets_take /var/lib/warren/.warren workspace.env /run/warren/secrets.env
else
    warren_secrets_take /var/lib/warren/.warren workspace.env
fi
if [ -d /var/lib/warren/.warren ] && [ ! -L /var/lib/warren/.warren ]; then
    /bin/rm -f /var/lib/warren/.warren/git-init.env
fi

# AD3: started as root (unless the task definition sets `user`), take ownership of the
# volume mount points, then re-exec as warren. Nothing workspace-controlled runs as root.
if [ "$(/usr/bin/id -u)" = 0 ]; then
    /usr/local/bin/warren-init-volume
    # AH1: when git-init materialized checkouts, swap the image's empty /workspace
    # directory for a link to them, like the podman/docker runtimes' /workspace. Done here
    # because uid 1000 can't write /. Root only replaces an empty directory in the image's
    # own filesystem with a link to the fixed volume path (ecs_git.WORKSPACE_DIR); it never
    # reads, follows or writes anything on the agent-writable volume. A non-empty or
    # already-replaced /workspace is left alone, and the shell cds to the checkout instead.
    if [ "${WARREN_WORKSPACE_DIR:-}" = /var/lib/warren/workspace ] && [ -d /workspace ] \
        && [ ! -L /workspace ]; then
        /bin/rmdir /workspace 2>/dev/null && /bin/ln -s /var/lib/warren/workspace /workspace || true
    fi
    # AG2a: the warren shell reads its harness settings from here when an ECS Exec
    # session doesn't carry the task env. Root-owned; only plain values are copied.
    /bin/mkdir -p /etc/warren
    : > /etc/warren/session.env
    for _v in WARREN_HARNESSES WARREN_HARNESS_ROOT WARREN_HARNESS_DEFAULT \
        WARREN_PROJECT WARREN_TEMPLATE WARREN_WORKSPACE_ID; do
        eval "_val=\${$_v:-}"
        case "$_val" in ''|*[!A-Za-z0-9\ ._/:-]*) continue ;; esac
        printf "%s='%s'\n" "$_v" "$_val" >> /etc/warren/session.env
    done
    HOME=/home/warren
    export HOME
    exec /sbin/su-exec warren:warren /usr/local/bin/entrypoint.sh "$@"
fi

# AB1/AG3: harness dirs on the volume keep only their declared persist paths (minus
# credential files), and warren rewrites its own generated config (e.g. a minimal
# .claude.json) from the image's profile data. Runs as warren; never follows a link.
if [ -n "${WARREN_HARNESSES:-}" ] && [ -x /usr/local/bin/warren-harness-init ]; then
    /usr/local/bin/warren-harness-init /var/lib/warren/harness || true
fi

# WARREN_APP_CMD (+ optional WARREN_APP_PORT) — set by ECSRuntime.provision() only when
# the connected intent declares a `port` (IntentConfig.port in
# warren_common/models.py): that's the signal this is an automated-agent workspace, not a
# plain dev/observe one, and the entrypoint should launch the app eagerly rather than wait
# for a human to attach. A plain interactive workspace has no WARREN_APP_CMD set — this
# entrypoint has nothing to run proactively for it ("an ECS task shouldn't need an
# entrypoint to run anything unless it's an automated process like an agent"), so it just
# stays alive for `aws ecs execute-command` to attach to.
#
# AH1: WARREN_WORKSPACE_DIR is set when the task's git-init container materialized
# checkouts onto the volume. The root phase above linked /workspace to it; if it couldn't
# (task started as non-root via WARREN_ECS_TASK_USER, or an image put files in
# /workspace), start in the checkout directly.
if [ -n "${WARREN_WORKSPACE_DIR:-}" ] && [ -d "$WARREN_WORKSPACE_DIR" ]; then
    if [ -L /workspace ]; then
        cd /workspace
    else
        cd "$WARREN_WORKSPACE_DIR"
    fi
fi

# AG2b: a `kind: agent` workspace runs its harness under warren's supervisor (restart
# policy, exits recorded, loopback ACP endpoint). The supervisor, not the harness, is
# this process; a human attaches the warren shell next to it with warren-session.
if [ -n "${WARREN_AGENT_SPEC:-}" ]; then
    _py=$(command -v python3 || true)
    if [ -z "$_py" ]; then
        echo "entrypoint: agent workspaces need python3 in the image for warren-agent-supervisor" >&2
        exit 1
    fi
    exec "$_py" /usr/local/bin/warren-agent-supervisor
fi

if [ -n "$WARREN_APP_CMD" ]; then
    # exec, not a backgrounded job: this process is PID 1 (no init layer in this image —
    # ECSRuntime.provision() sets Fargate's own initProcessEnabled for zombie reaping
    # instead), so the agent process itself must be PID 1 to receive SIGTERM directly on
    # task stop rather than an orphaned shell eating the signal.
    exec sh -c "$WARREN_APP_CMD"
fi

exec tail -f /dev/null
