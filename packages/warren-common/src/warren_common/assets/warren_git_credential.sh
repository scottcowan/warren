#!/bin/sh
# git-credential-warren: git credential helper for `git_write: true` workspaces.
# Installed at /usr/local/bin/git-credential-warren and configured in the system
# gitconfig for https://github.com only (credential.https://github.com.helper, with
# useHttpPath so git passes the repo path). The control plane keeps one short-lived,
# repo-scoped GitHub App installation token per owner in /run/warren-git/<owner>
# (0600, the workspace user) and replaces it before it expires. This helper holds no
# token itself: on `get` it prints the owner's file, otherwise nothing, so git falls
# through to its other helpers or fails. `store` and `erase` are no-ops.
# gh CLI: GH_TOKEN="$(cat /run/warren-git/<owner>)" gh pr create ...
[ "${1:-}" = get ] || exit 0
dir=${WARREN_GIT_TOKEN_DIR:-/run/warren-git}
protocol=""; host=""; path=""
while IFS= read -r line; do
    [ -n "$line" ] || break
    case "$line" in
        protocol=*) protocol=${line#protocol=} ;;
        host=*) host=${line#host=} ;;
        path=*) path=${line#path=} ;;
    esac
done
[ "$protocol" = https ] && [ "$host" = github.com ] || exit 0
owner=$(printf '%s' "${path%%/*}" | tr 'A-Z' 'a-z')
case "$owner" in ''|-*|*[!a-z0-9-]*) exit 0 ;; esac
file="$dir/$owner"
[ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || exit 0
token=""
IFS= read -r token < "$file" || [ -n "$token" ] || exit 0
case "$token" in ''|*[!A-Za-z0-9_]*) exit 0 ;; esac
printf 'username=x-access-token\npassword=%s\n' "$token"
