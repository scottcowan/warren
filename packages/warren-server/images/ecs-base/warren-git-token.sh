#!/bin/sh
# warren-git-token: installs or removes a `git_write: true` workspace's GitHub tokens
# (src/warren/git/write_tokens.py) in /run/warren-git/<owner>: the container's own
# filesystem, not the volume; dir root 0755, files 0600 owned by the workspace user.
#
#   warren-git-token install            "<owner> <token>" lines on stdin (entrypoint,
#                                       from the launch-time secrets)
#   warren-git-token install-envelope   WARREN_SECRETS_BLOB + WARREN_WORKSPACE_ID in the
#                                       environment: a KMS envelope holding
#                                       WARREN_GIT_TOKENS (control-plane refresh over
#                                       ECS Exec, which records only that ciphertext)
#   warren-git-token remove             drop every token file (stop/destroy)
#
# Run as root (the entrypoint's root phase, or ECS Exec). Tokens are never printed or
# passed as arguments: only a count goes to stdout.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset ENV BASH_ENV
set -eu

dir=/run/warren-git
uid=1000
decrypt=/usr/local/bin/warren-secrets-decrypt
if [ "$(id -u)" != 0 ]; then
    # Test hooks only: as root (every real use) the paths are fixed.
    dir=${WARREN_GIT_TOKEN_DIR:-$dir}
    decrypt=${WARREN_SECRETS_DECRYPT:-$decrypt}
fi
fail() { echo "warren-git-token: $1" >&2; exit 1; }

prepare_dir() {
    [ ! -L "$dir" ] || fail "$dir is a symlink"
    (umask 022 && mkdir -p "$dir") || fail "cannot create $dir"
    [ -d "$dir" ] && [ ! -L "$dir" ] || fail "$dir is not a directory"
    chmod 0755 "$dir"
}

# stdin: "<owner> <token>" lines. Each file is written to a mktemp file in $dir
# (O_EXCL, so nothing pre-planted is followed), chowned, then renamed into place.
install_lines() {
    prepare_dir
    n=0
    owner=""; token=""
    while IFS=' ' read -r owner token || [ -n "$owner" ]; do
        case "$owner" in ''|-*|*[!a-z0-9-]*) owner=""; continue ;; esac
        case "$token" in ''|*[!A-Za-z0-9_]*) owner=""; continue ;; esac
        tmp=$(mktemp "$dir/.tmp.XXXXXX") || fail "cannot create a temp file"
        printf '%s\n' "$token" > "$tmp"
        if [ "$(id -u)" = 0 ]; then
            chown "$uid:$uid" "$tmp" || { rm -f "$tmp"; fail "cannot chown"; }
        fi
        chmod 0600 "$tmp"
        mv -f "$tmp" "$dir/$owner"
        n=$((n + 1))
        owner=""; token=""
    done
    echo "warren-git-token: installed $n"
}

# ECS Exec sessions don't carry the task's environment; the task-role credentials
# endpoint is read from PID 1's (root only).
task_credentials() {
    [ -z "${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:-}${AWS_CONTAINER_CREDENTIALS_FULL_URI:-}" ] || return 0
    [ -r /proc/1/environ ] || return 0
    for _v in AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_CREDENTIALS_FULL_URI \
        AWS_CONTAINER_AUTHORIZATION_TOKEN; do
        _val=$(tr '\0' '\n' < /proc/1/environ | sed -n "s/^$_v=//p" | head -n 1)
        [ -z "$_val" ] || export "$_v=$_val"
    done
    unset _v _val
}

install_envelope() {
    [ -n "${WARREN_SECRETS_BLOB:-}" ] || fail "no WARREN_SECRETS_BLOB"
    [ -n "${WARREN_WORKSPACE_ID:-}" ] || fail "no WARREN_WORKSPACE_ID"
    task_credentials
    out=$("$decrypt" workspace) || fail "cannot decrypt the token envelope"
    unset WARREN_SECRETS_BLOB
    b64=$(printf '%s\n' "$out" | sed -n 's/^WARREN_GIT_TOKENS=//p' | head -n 1)
    out=""
    case "$b64" in ''|*[!A-Za-z0-9+/=]*) fail "no tokens in the envelope" ;; esac
    printf '%s' "$b64" | base64 -d | install_lines
}

case "${1:-}" in
    install) install_lines ;;
    install-envelope) install_envelope ;;
    remove)
        [ ! -L "$dir" ] || fail "$dir is a symlink"
        rm -rf -- "$dir"
        echo "warren-git-token: removed"
        ;;
    *) echo "usage: warren-git-token install|install-envelope|remove" >&2; exit 2 ;;
esac
