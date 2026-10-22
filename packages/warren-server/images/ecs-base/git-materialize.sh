#!/bin/sh
# AH1: runs as the `git-init` container of an ECS workspace task (runtime/ecs_git.py),
# before the workspace container starts (dependsOn SUCCESS). Only this container is given
# the clone credentials; the workspace container never is.
#
# WARREN_GIT_FOLDERS: one tab-separated record per line, every field non-empty ("-" = unset):
#   kind(worktree|clone) name mount url branch ws_branch cred_kind(pat|ssh|none) cred_env
#
# Layout under the workspace's EFS access point ($WARREN_GIT_ROOT, /var/lib/warren):
#   git/<name>.git-store   bare clone (worktree folders)
#   workspace/<mount>      worktree on ws_branch, or a plain clone (clone folders)
#
# Re-runs on every task launch against the same volume, so everything already on it is
# agent-written and untrusted. Credentials never meet it:
#   1. Copy the credentials ECS injected into 0600 files in a container-local private dir,
#      then re-exec with an empty environment (and, if started as root, as uid 1000 via
#      su-exec). After execve /proc/1/environ no longer holds them.
#   2. Clone over the network into fresh repos in that private dir (no checkout, so no
#      filters), never into or from anything on the volume. Then delete the credentials.
#   3. Only then touch the volume: move fresh clones into place, rewrite a reused bare
#      store's config from scratch (dropping filter drivers, includes, sshCommand, ...)
#      and run local git with hooks, fsmonitor, attributes files and all transports off.
# An existing checkout is never touched and an existing bare store is never fetched.
set -u

ROOT="${WARREN_GIT_ROOT:-/var/lib/warren}"
STORE="$ROOT/git"
WS_DIR="$ROOT/workspace"
ALLOW_PROTOCOL="${WARREN_GIT_ALLOW_PROTOCOL:-https:ssh}"
# SSH host keys: GitHub's published keys baked into the image (images/ecs-base/ssh_known_hosts),
# plus any extra known_hosts lines the operator supplies in WARREN_GIT_KNOWN_HOSTS
# (settings.ecs_git_known_hosts). An unknown host key fails the clone; nothing is learned.
PINNED_KNOWN_HOSTS=/etc/warren/ssh_known_hosts
WARREN_UID=1000
SU_EXEC=/sbin/su-exec
INIT_VOLUME=/usr/local/bin/warren-init-volume
# The same fixed-name pins as host-side git (warren_common.safe_git.SAFE_GIT_CONFIG; a
# unit test keeps the two in step), applied to every git call here. Values never contain
# whitespace or glob characters, so the list is word-split unquoted.
SAFE_GIT_PINS="-c core.hooksPath=/dev/null -c core.fsmonitor=false -c protocol.ext.allow=never
 -c core.sshCommand=ssh -c core.askPass= -c core.pager=cat -c core.editor=: -c sequence.editor=:
 -c core.alternateRefsCommand= -c diff.external= -c gpg.program=false -c gpg.ssh.program=false
 -c gpg.x509.program=false -c log.showSignature=false -c merge.verifySignatures=false
 -c submodule.recurse=false -c fetch.recurseSubmodules=false -c credential.helper="
TAB=$(printf '\t')
NL='
'

log() { printf 'warren-git-materialize: %s\n' "$*" >&2; }

# Calls "$1 <index> <8 record fields>" for each WARREN_GIT_FOLDERS record.
each_record() {
    cb=$1
    idx=0
    old_ifs=$IFS
    IFS=$NL
    for rec in ${WARREN_GIT_FOLDERS:-}; do
        idx=$((idx + 1))
        IFS=$TAB
        # shellcheck disable=SC2086
        set -- $rec
        IFS=$old_ifs
        if [ $# -ne 8 ]; then
            [ "$cb" = materialize_one ] && { log "skipping malformed record"; failed=$((failed + 1)); }
            continue
        fi
        "$cb" "$idx" "$@"
    done
    IFS=$old_ifs
}

valid_cred_name() {
    case "$1" in ''|-|*[!A-Za-z0-9_]*|[0-9]*) return 1 ;; esac
}

# --- stage 1: capture credentials, scrub the environment, drop root -------------------

stash_cred() {
    cenv=$9
    valid_cred_name "$cenv" || return 0
    eval "val=\${$cenv:-}"
    [ -n "$val" ] && printf '%s\n' "$val" > "$PRIV/creds/$cenv"
    unset val
}

if [ "${1:-}" != --scrubbed ]; then
    case "$0" in /*) SELF=$0 ;; *) SELF="$(pwd)/$0" ;; esac
    umask 077
    PRIV=$(mktemp -d /tmp/warren-git.XXXXXX) && mkdir "$PRIV/creds" || { log "cannot create private dir"; exit 1; }
    each_record stash_cred
    printf '%s\n' "${WARREN_GIT_KNOWN_HOSTS:-}" > "$PRIV/known_hosts_extra"
    drop=
    if [ "$(id -u)" = 0 ]; then
        [ -x "$SU_EXEC" ] || { log "running as root but $SU_EXEC is missing; refusing to run git as root"; rm -rf "$PRIV"; exit 1; }
        [ -x "$INIT_VOLUME" ] || { log "running as root but $INIT_VOLUME is missing; refusing"; rm -rf "$PRIV"; exit 1; }
        # A fresh non-EFS task volume is root-owned: hand its mount point to the workspace
        # user with the same root routine the workspace entrypoint uses (AD3). It changes
        # only the mount point itself, never recursively or through a link. Everything on
        # the volume (workspace/, git/, repo content) is then created as uid 1000 in stage 2.
        "$INIT_VOLUME" || { log "$INIT_VOLUME failed"; rm -rf "$PRIV"; exit 1; }
        chown -R "$WARREN_UID:$WARREN_UID" "$PRIV"
        drop="$SU_EXEC $WARREN_UID:$WARREN_UID"
    fi
    # shellcheck disable=SC2086
    exec env -i PATH="${PATH:-/usr/local/bin:/usr/bin:/bin}" WARREN_GIT_ROOT="$ROOT" \
        WARREN_GIT_ALLOW_PROTOCOL="$ALLOW_PROTOCOL" WARREN_GIT_FOLDERS="${WARREN_GIT_FOLDERS:-}" \
        WARREN_GIT_PRIV="$PRIV" $drop /bin/sh "$SELF" --scrubbed
fi

# --- stage 2: empty environment, credentials only in $PRIV/creds ----------------------

PRIV=$WARREN_GIT_PRIV
trap 'rm -rf "$PRIV"' EXIT
umask 022
cd "$PRIV" || exit 1

for d in "$WS_DIR" "$STORE"; do
    if [ -L "$d" ] || ! mkdir -p "$d" 2>/dev/null || [ ! -w "$d" ]; then
        owner=$(ls -ldn "$ROOT" 2>/dev/null | awk '{print $3}')
        log "$d is not writable by uid $(id -u) ($ROOT is owned by uid ${owner:-?});" \
            "start git-init as root or give the volume to uid $WARREN_UID. Nothing materialized."
        exit 1
    fi
done

git_env() {
    env -i PATH="$PATH" HOME=/nonexistent GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
        GIT_ATTR_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 "$@"
}

# Local-only git on agent-written repos: no transport at all, no hooks, no attribute files.
git_local() {
    # shellcheck disable=SC2086
    git_env git $SAFE_GIT_PINS -c core.attributesFile=/dev/null -c protocol.allow=never "$@"
}

is_ssh() { case "$1" in ssh://*|git+ssh://*|ssh+git://*) return 0 ;; *://*) return 1 ;; *:*) return 0 ;; esac; return 1; }

# ssh for clones: pinned host keys only, never trust-on-first-use, no ~/.ssh or /etc/ssh config.
ssh_command() {
    printf 'ssh -F /dev/null -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=%s %s"' \
        "$PINNED_KNOWN_HOSTS" "$PRIV/known_hosts_extra"
    printf ' -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no -o CheckHostIP=no -o BatchMode=yes'
    [ -n "${1:-}" ] && printf ' -o IdentitiesOnly=yes -i %s' "$1"
}

# Network clone into a fresh dir under $PRIV: no existing repo config to trust.
git_clone() {
    url=$1; ckind=$2; cenv=$3; dest=$4; shift 4
    cred="$PRIV/creds/$cenv"
    if [ "$ckind" != none ] && [ ! -s "$cred" ]; then
        log "credential $cenv not set, cloning without it"
        ckind=none
    fi
    if is_ssh "$url" && [ ! -s "$PINNED_KNOWN_HOSTS" ] && ! grep -q '[^[:space:]]' "$PRIV/known_hosts_extra"; then
        log "no pinned ssh known_hosts ($PINNED_KNOWN_HOSTS missing, WARREN_GIT_KNOWN_HOSTS unset); refusing to clone $url"
        return 1
    fi
    # GIT_SSH_COMMAND / GIT_ASKPASS below take precedence over the core.sshCommand /
    # core.askPass pins. --upload-pack matches host-side fetches (safe_git).
    # shellcheck disable=SC2086
    set -- $SAFE_GIT_PINS clone --upload-pack=git-upload-pack "$@"
    case "$ckind" in
        pat)
            printf '#!/bin/sh\nexec cat "%s"\n' "$cred" > "$PRIV/creds/askpass"
            chmod 0700 "$PRIV/creds/askpass"
            auth_url=$(printf '%s' "$url" | sed 's#^https://#https://x-access-token@#')
            git_env GIT_ALLOW_PROTOCOL="$ALLOW_PROTOCOL" GIT_ASKPASS="$PRIV/creds/askpass" \
                git "$@" -- "$auth_url" "$dest"
            ;;
        ssh)
            git_env GIT_ALLOW_PROTOCOL="$ALLOW_PROTOCOL" GIT_SSH_COMMAND="$(ssh_command "$cred")" \
                git "$@" -- "$url" "$dest"
            ;;
        *)
            git_env GIT_ALLOW_PROTOCOL="$ALLOW_PROTOCOL" GIT_SSH_COMMAND="$(ssh_command)" \
                git "$@" -- "$url" "$dest"
            ;;
    esac
}

# Sets target/bare. Returns 0 if the folder needs work, 2 if its checkout already exists.
precheck() {
    kind=$1; name=$2; mount=$3; ckind=$7; cenv=$8
    valid_cred_name "$cenv" || cenv=-
    [ "$cenv" = - ] && [ "$8" != - ] && { log "$name: bad credential name"; return 1; }
    case "$ckind" in pat|ssh) [ "$cenv" != - ] || ckind=none ;; *) ckind=none ;; esac
    case "$name/$mount" in *..*|/*|-*) log "$name: unsafe name or mount"; return 1 ;; esac
    case "$4$5$6" in *"$NL"*|*"$TAB"*) log "$name: bad record"; return 1 ;; esac
    target="$WS_DIR/$mount"
    bare="$STORE/$name.git-store"
    [ -e "$target/.git" ] && return 2
    if [ -d "$target" ] && [ -n "$(ls -A "$target" 2>/dev/null)" ]; then
        log "$name: $target is not empty and not a checkout, refusing to overwrite"
        return 1
    fi
    return 0
}

fetch() {
    idx=$1; shift
    precheck "$@" || return 0
    url=$4; branch=$5
    if [ "$1" = clone ]; then
        git_clone "$url" "$ckind" "$cenv" "$PRIV/$idx" --no-checkout --branch "$branch"
    elif [ ! -d "$bare" ]; then
        git_clone "$url" "$ckind" "$cenv" "$PRIV/$idx" --bare
    else
        return 0
    fi || {
        rm -rf "${PRIV:?}/$idx"
        if is_ssh "$url"; then
            log "$2: clone failed (an ssh host key not in $PINNED_KNOWN_HOSTS or WARREN_GIT_KNOWN_HOSTS is rejected)"
        else
            log "$2: clone failed"
        fi
    }
}

# Replace an agent-writable bare store's config with one warren wrote: nothing in it can
# name a program (filter drivers, sshCommand, include.path, uploadpack, ...).
sanitize_store() {
    if [ -L "$bare" ] || [ -L "$bare/config" ] || [ ! -f "$bare/config" ] || [ ! -f "$bare/HEAD" ]; then
        log "$name: $bare is not a bare repository"
        return 1
    fi
    old="$bare/config"
    fmt=$(git_env git config --file "$old" --get extensions.objectformat 2>/dev/null)
    refs=$(git_env git config --file "$old" --get extensions.refstorage 2>/dev/null)
    case "$fmt" in sha1|sha256) ;; *) fmt= ;; esac
    case "$refs" in files|reftable) ;; *) refs= ;; esac
    new="$PRIV/config.$name"
    : > "$new"
    set_cfg() { git_env git config --file "$new" "$@"; }
    set_cfg core.repositoryformatversion "$([ -n "$fmt$refs" ] && echo 1 || echo 0)"
    set_cfg core.bare true
    set_cfg core.hooksPath /dev/null
    set_cfg core.fsmonitor false
    set_cfg core.attributesFile /dev/null
    set_cfg gc.auto 0
    set_cfg remote.origin.url "$url"
    [ -n "$fmt" ] && set_cfg extensions.objectformat "$fmt"
    [ -n "$refs" ] && set_cfg extensions.refstorage "$refs"
    rm -f "$bare/commondir" "$bare/config.worktree"
    mv -f "$new" "$old"
}

materialize() {
    idx=$1; shift
    precheck "$@"
    case $? in
        2) log "$name: checkout exists at $target, leaving it untouched"; return 0 ;;
        1) return 1 ;;
    esac
    kind=$1; url=$4; branch=$5; ws_branch=$6
    src="$PRIV/$idx"
    mkdir -p "$(dirname "$target")" || return 1

    if [ "$kind" = clone ]; then
        [ -d "$src" ] || return 1
        rm -rf "$target.partial"
        mv "$src" "$target.partial" || return 1
        git_local -C "$target.partial" remote set-url origin "$url" &&
            git_local -C "$target.partial" remote set-url --push origin no_push &&
            git_local -C "$target.partial" reset -q --hard ||
            { rm -rf "$target.partial"; return 1; }
        rmdir "$target" 2>/dev/null
        mv "$target.partial" "$target" || return 1
        log "$name: cloned $branch into $target"
        return 0
    fi

    if [ ! -d "$bare" ]; then
        [ -d "$src" ] || return 1
        rm -rf "$bare.partial"
        mv "$src" "$bare.partial" && mv "$bare.partial" "$bare" || return 1
    fi
    sanitize_store || return 1
    git_local -C "$bare" worktree prune
    rmdir "$target" 2>/dev/null
    if git_local -C "$bare" rev-parse --verify -q "refs/heads/$ws_branch" >/dev/null; then
        # Branch survives from an earlier launch (it may hold the user's commits): reuse it.
        git_local -C "$bare" worktree add "$target" "$ws_branch" || return 1
    else
        git_local -C "$bare" worktree add -b "$ws_branch" "$target" "$branch" || return 1
    fi
    log "$name: worktree on $ws_branch (from $branch) at $target"
}

each_record fetch
rm -rf "$PRIV/creds"

materialize_one() {
    materialize "$@" || { log "$3: materialization failed, skipping"; failed=$((failed + 1)); }
}

failed=0
each_record materialize_one
log "done ($failed failed)"
exit 0
