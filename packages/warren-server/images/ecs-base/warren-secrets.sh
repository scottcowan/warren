# Sourced (never executed) by entrypoint.sh, warren-session and warren-git-materialize.
# Reads the secrets file the control plane writes onto the task's volume just before
# RunTask (src/warren/runtime/ecs_secrets.py): one `NAME=<base64 value>` per line.
# Nothing in it is ever evaluated: names must be environment variable names, values
# must be base64 and are decoded with base64 -d. Values are never printed or logged.

# warren_secrets_load FILE: export each secret in FILE into this shell.
warren_secrets_load() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ -r "$1" ] || return 0
    while IFS= read -r _ws_line || [ -n "$_ws_line" ]; do
        _ws_name=${_ws_line%%=*}
        [ "$_ws_name" != "$_ws_line" ] || continue
        _ws_b64=${_ws_line#*=}
        case "$_ws_name" in ''|[0-9]*|*[!A-Za-z0-9_]*) continue ;; esac
        case "$_ws_b64" in *[!A-Za-z0-9+/=]*) continue ;; esac
        # The trailing x keeps a value's own trailing newlines through $(...).
        _ws_val=$(printf '%s' "$_ws_b64" | PATH=/usr/sbin:/usr/bin:/sbin:/bin base64 -d 2>/dev/null && printf x) || continue
        case "$_ws_val" in *x) _ws_val=${_ws_val%x} ;; *) continue ;; esac
        export "$_ws_name=$_ws_val"
    done < "$1"
    unset _ws_line _ws_name _ws_b64 _ws_val
}

# warren_secrets_take DIR NAME [COPY]: load DIR/NAME, optionally copy it to COPY
# (created 0600), then delete it. A DIR that is a symlink is never read or touched.
warren_secrets_take() {
    [ -d "$1" ] && [ ! -L "$1" ] || return 0
    warren_secrets_load "$1/$2"
    if [ -n "${3:-}" ] && [ -f "$1/$2" ] && [ ! -L "$1/$2" ]; then
        (umask 077 && /bin/mkdir -p "${3%/*}" && /bin/cat "$1/$2" > "$3") || true
    fi
    /bin/rm -f "$1/$2"
}
