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
#   1. Copy the credentials from git-init.env (then deleted), or in EBS mode from the
#      decrypted WARREN_SECRETS_BLOB, into 0600 files in a container-local private dir,
#      then re-exec with an empty environment (and, if started as root, as uid 1000 via
#      su-exec). After execve /proc/1/environ no longer holds them.
#   2. Clone over the network into fresh repos in that private dir (no checkout, so no
#      filters), never into or from anything on the volume. Then delete the credentials.
#   3. Only then touch the volume: move fresh clones into place, rewrite a reused bare
#      store's config from scratch (dropping filter drivers, includes, sshCommand, ...)
#      and run local git with hooks, fsmonitor, attributes files and all transports off.
# An existing checkout is never touched and an existing bare store is never fetched.
#
# EBS bare seeds (runtime/ebs_seeds.py, WARREN_ECS_EBS_BARE_SEEDS):
#   .warren-bares/<host>/<path>.git   bare mirrors of the owner's repos (seed_key below)
# A new EBS workspace's volume may be created from its owner's seed snapshot; the control
# plane then sets WARREN_GIT_SEEDED=1. Only on such a launch, and only if the volume
# holds nothing but the seed (the workspace container has never run on it), git-init
# clones each folder from its seed bare (hardlinks, same filesystem) into a staging dir
# whose config it wrote, fetches just the delta with the credentials, and then
# materializes as usual. A seed bare that looks wrong (not a bare repo, symlinks,
# alternates, another remote) is discarded and the folder is cloned over the network.
# Afterwards the whole seed directory is deleted, so the workspace never holds it and
# its own snapshots don't carry it. On any other launch a seed directory is planted or
# left over and is deleted unread.
#
# WARREN_GIT_MODE=refresh-seed: run by the seed-refresh task instead (git-init container
# only, a volume from the owner's previous seed or empty, never mounted by a workspace).
# WARREN_GIT_SEED_REPOS: one tab-separated record per line: key url cred_kind cred_env.
# Creates or `fetch --prune`s each listed bare mirror, deletes everything else on the
# volume, exits 0 (all fetched) or 3 (some failed; the rest are still kept).
#
# WARREN_GIT_CLONE_FILTER (blob:none|tree:0): partial network clones. The workspace never
# holds the clone credentials, so for a private repo every later lazy fetch (checking
# out another commit, log -p, blame) fails inside it; off unless the operator opts in.
set -u

ROOT="${WARREN_GIT_ROOT:-/var/lib/warren}"
STORE="$ROOT/git"
WS_DIR="$ROOT/workspace"
SEEDS="$ROOT/.warren-bares"
STAGE="$ROOT/.warren-stage"
MODE="${WARREN_GIT_MODE:-materialize}"
SEEDED="${WARREN_GIT_SEEDED:-}"
CLONE_FILTER="${WARREN_GIT_CLONE_FILTER:-}"
case "$CLONE_FILTER" in blob:none|tree:0) ;; *) CLONE_FILTER= ;; esac
ALLOW_PROTOCOL="${WARREN_GIT_ALLOW_PROTOCOL:-https:ssh}"
# SSH host keys: GitHub's published keys baked into the image (images/ecs-base/ssh_known_hosts),
# plus any extra known_hosts lines the operator supplies in WARREN_GIT_KNOWN_HOSTS
# (settings.ecs_git_known_hosts). An unknown host key fails the clone; nothing is learned.
PINNED_KNOWN_HOSTS=/etc/warren/ssh_known_hosts
WARREN_UID=1000
SU_EXEC=/sbin/su-exec
INIT_VOLUME=/usr/local/bin/warren-init-volume
SECRETS_LIB=/usr/local/lib/warren/secrets.sh
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

# Calls "$1 <index> <4 record fields>" for each WARREN_GIT_SEED_REPOS record.
each_seed() {
    cb=$1
    idx=0
    old_ifs=$IFS
    IFS=$NL
    for rec in ${WARREN_GIT_SEED_REPOS:-}; do
        idx=$((idx + 1))
        IFS=$TAB
        # shellcheck disable=SC2086
        set -- $rec
        IFS=$old_ifs
        if [ $# -ne 4 ]; then
            [ "$cb" = refresh_one ] && { log "skipping malformed seed record"; failed=$((failed + 1)); }
            continue
        fi
        "$cb" "$idx" "$@"
    done
    IFS=$old_ifs
}

valid_cred_name() {
    case "$1" in ''|-|*[!A-Za-z0-9_]*|[0-9]*) return 1 ;; esac
}

# A repo's seed path under $SEEDS: <host>/<path>, lowercased, without userinfo, port,
# scheme or a trailing .git. Must match runtime/ebs_seeds.seed_key (a unit test runs
# both). Prints nothing and fails for anything else.
seed_key() {
    k=$1
    case "$k" in ''|*[!A-Za-z0-9._~:/@+-]*) return 1 ;; esac
    case "$k" in
        https://*|ssh://*|file://*)
            k=${k#*://}
            first=${k%%/*}
            rest=${k#"$first"}
            k=${first##*@}$rest
            ;;
        *://*) return 1 ;;
        *:*)
            first=${k%%:*}
            k=${first##*@}/${k#*:}
            ;;
        *) return 1 ;;
    esac
    while :; do case "$k" in /*) k=${k#/} ;; *) break ;; esac; done
    k=${k%/}
    k=${k%.git}
    k=$(printf '%s' "$k" | tr 'A-Z' 'a-z')
    case "$k" in ''|*[!a-z0-9._/-]*|*//*|*/) return 1 ;; esac
    # No component may start with . or -, or end in .git (a bare inside a bare).
    case "/$k/" in */.*|*/-*|*.git/*) return 1 ;; esac
    case "$k" in */*) ;; *) return 1 ;; esac
    printf '%s\n' "$k"
}

# Test hook (no environment, no volume): print the seed key of a URL.
if [ "${1:-}" = --seed-key ]; then
    seed_key "${2:-}"
    exit $?
fi

# --- stage 1: capture credentials, scrub the environment, drop root -------------------

stash_cred() {
    eval "cenv=\${$#}"
    valid_cred_name "$cenv" || return 0
    eval "val=\${$cenv:-}"
    [ -n "$val" ] && printf '%s\n' "$val" > "$PRIV/creds/$cenv"
    unset val
}

if [ "${1:-}" != --scrubbed ]; then
    case "$0" in /*) SELF=$0 ;; *) SELF="$(pwd)/$0" ;; esac
    umask 077
    PRIV=$(mktemp -d /tmp/warren-git.XXXXXX) && mkdir "$PRIV/creds" || { log "cannot create private dir"; exit 1; }
    # The clone credentials arrive as $ROOT/.warren/git-init.env, written by the control
    # plane just before RunTask (runtime/ecs_secrets.py). Load and delete it first, so it
    # is gone before the workspace container (dependsOn this one) starts.
    # EBS mode (runtime/ecs_kms_secrets.py): they arrive instead as KMS-wrapped
    # ciphertext in WARREN_SECRETS_BLOB, encrypted for this container only. Decrypt into
    # the private dir, load, delete. Fails closed. `env -i` below drops the blob too.
    if [ -r "$SECRETS_LIB" ]; then
        . "$SECRETS_LIB"
        if [ -n "${WARREN_SECRETS_BLOB:-}" ]; then
            /usr/local/bin/warren-secrets-decrypt git-init > "$PRIV/secrets.env" \
                || { log "cannot decrypt git-init secrets"; rm -rf "$PRIV"; exit 1; }
            unset WARREN_SECRETS_BLOB
            warren_secrets_load "$PRIV/secrets.env"
            rm -f "$PRIV/secrets.env"
            # The control plane never writes an EBS volume: a file there is planted.
            if [ -d "$ROOT/.warren" ] && [ ! -L "$ROOT/.warren" ]; then
                rm -f "$ROOT/.warren/git-init.env"
            fi
        else
            warren_secrets_take "$ROOT/.warren" git-init.env
        fi
    elif [ -n "${WARREN_SECRETS_BLOB:-}" ]; then
        log "$SECRETS_LIB missing; cannot load git-init secrets"; rm -rf "$PRIV"; exit 1
    fi
    if [ "$MODE" = refresh-seed ]; then each_seed stash_cred; else each_record stash_cred; fi
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
        WARREN_GIT_MODE="$MODE" WARREN_GIT_SEEDED="$SEEDED" WARREN_GIT_CLONE_FILTER="$CLONE_FILTER" \
        WARREN_GIT_SEED_REPOS="${WARREN_GIT_SEED_REPOS:-}" \
        WARREN_GIT_PRIV="$PRIV" $drop /bin/sh "$SELF" --scrubbed
fi

# --- stage 2: empty environment, credentials only in $PRIV/creds ----------------------

PRIV=$WARREN_GIT_PRIV
trap 'rm -rf "$PRIV"' EXIT
umask 022
cd "$PRIV" || exit 1

not_writable() {
    owner=$(ls -ldn "$ROOT" 2>/dev/null | awk '{print $3}')
    log "$1 is not writable by uid $(id -u) ($ROOT is owned by uid ${owner:-?});" \
        "start git-init as root or give the volume to uid $WARREN_UID. Nothing materialized."
    exit 1
}

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

# net_git URL CRED_KIND CRED_ENV GIT_ARGS...: `git <pins> GIT_ARGS` with URL's transport
# credentials; the argument @URL@ stands for URL (with the PAT username for https). Only
# ever run on repos whose config git-init wrote: fresh clones, seed-refresh mirrors, or
# (bare seeds) repos git-init itself cloned locally from a seed bare it validated.
net_git() {
    n_url=$1; n_kind=$2; n_cred="$PRIV/creds/$3"; shift 3
    if [ "$n_kind" != none ] && [ ! -s "$n_cred" ]; then
        log "credential ${n_cred##*/} not set, cloning without it"
        n_kind=none
    fi
    if is_ssh "$n_url" && [ ! -s "$PINNED_KNOWN_HOSTS" ] && ! grep -q '[^[:space:]]' "$PRIV/known_hosts_extra"; then
        log "no pinned ssh known_hosts ($PINNED_KNOWN_HOSTS missing, WARREN_GIT_KNOWN_HOSTS unset); refusing to clone $n_url"
        return 1
    fi
    n_use=$n_url
    [ "$n_kind" = pat ] && n_use=$(printf '%s' "$n_url" | sed 's#^https://#https://x-access-token@#')
    for n_arg; do
        shift
        [ "$n_arg" = @URL@ ] && n_arg=$n_use
        set -- "$@" "$n_arg"
    done
    # GIT_SSH_COMMAND / GIT_ASKPASS below take precedence over the core.sshCommand /
    # core.askPass pins. No auto gc or maintenance after a fetch.
    # shellcheck disable=SC2086
    set -- $SAFE_GIT_PINS -c gc.auto=0 -c maintenance.auto=false "$@"
    case "$n_kind" in
        pat)
            printf '#!/bin/sh\nexec cat "%s"\n' "$n_cred" > "$PRIV/creds/askpass"
            chmod 0700 "$PRIV/creds/askpass"
            git_env GIT_ALLOW_PROTOCOL="$ALLOW_PROTOCOL" GIT_ASKPASS="$PRIV/creds/askpass" git "$@"
            ;;
        ssh)
            git_env GIT_ALLOW_PROTOCOL="$ALLOW_PROTOCOL" GIT_SSH_COMMAND="$(ssh_command "$n_cred")" git "$@"
            ;;
        *)
            git_env GIT_ALLOW_PROTOCOL="$ALLOW_PROTOCOL" GIT_SSH_COMMAND="$(ssh_command)" git "$@"
            ;;
    esac
}

# Network clone into a fresh dir (no existing repo config to trust). --upload-pack
# matches host-side fetches (safe_git).
git_clone() {
    c_url=$1; c_kind=$2; c_env=$3; c_dest=$4; shift 4
    net_git "$c_url" "$c_kind" "$c_env" clone --upload-pack=git-upload-pack "$@" -- @URL@ "$c_dest"
}

# git_fetch_into DIR HEADS_DST: fetch $url's heads (to HEADS_DST) and tags into DIR, a
# repo git-init created and configured itself.
git_fetch_into() {
    net_git "$url" "$ckind" "$cenv" -C "$1" fetch -q --prune --no-write-fetch-head \
        --upload-pack=git-upload-pack -- @URL@ "+refs/heads/*:$2" '+refs/tags/*:refs/tags/*'
}

# WARREN_GIT_CLONE_FILTER: a partial clone lacks the blobs its first checkout needs, and
# materialize() runs with no transport. Fetch exactly those now, with the credentials.
prefetch_blobs() {
    [ -n "$CLONE_FILTER" ] || return 0
    p_missing=$(git_local -C "$1" rev-list --objects --missing=print "$2^{tree}" 2>/dev/null | sed -n 's/^?//p')
    [ -n "$p_missing" ] || return 0
    printf '%s\n' "$p_missing" | net_git "$url" "$ckind" "$cenv" -C "$1" \
        -c fetch.negotiationAlgorithm=noop fetch -q --no-tags --no-write-fetch-head \
        --recurse-submodules=no --filter="$CLONE_FILTER" --upload-pack=git-upload-pack --stdin -- @URL@
}

# A bare repository with nothing git would follow elsewhere: no symlinks anywhere in it,
# no alternates, no commondir.
plain_bare() {
    [ -d "$1" ] && [ ! -L "$1" ] && [ -f "$1/config" ] && [ ! -L "$1/config" ] && [ -f "$1/HEAD" ] \
        && [ -d "$1/objects" ] && [ -d "$1/refs" ] && [ ! -e "$1/objects/info/alternates" ] \
        && [ ! -e "$1/objects/info/http-alternates" ] && [ ! -e "$1/commondir" ] \
        && [ -z "$(find "$1" -type l -print 2>/dev/null | head -n 1)" ]
}

# Replace a bare repo's config with one warren wrote: nothing in it can name a program
# (filter drivers, sshCommand, include.path, uploadpack, ...). Keeps only the object and
# ref formats, and a partial clone's promisor filter (WARREN_GIT_CLONE_FILTER).
write_bare_config() {
    w_old="$1/config"
    fmt=$(git_env git config --file "$w_old" --get extensions.objectformat 2>/dev/null)
    refs=$(git_env git config --file "$w_old" --get extensions.refstorage 2>/dev/null)
    promisor=$(git_env git config --file "$w_old" --get remote.origin.promisor 2>/dev/null)
    pfilter=$(git_env git config --file "$w_old" --get remote.origin.partialclonefilter 2>/dev/null)
    case "$fmt" in sha1|sha256) ;; *) fmt= ;; esac
    case "$refs" in files|reftable) ;; *) refs= ;; esac
    case "$promisor:$pfilter" in true:blob:none|true:tree:0) ;; *) pfilter= ;; esac
    w_new="$PRIV/config.new"
    : > "$w_new"
    set_cfg() { git_env git config --file "$w_new" "$@"; }
    set_cfg core.repositoryformatversion "$([ -n "$fmt$refs$pfilter" ] && echo 1 || echo 0)"
    set_cfg core.bare true
    set_cfg core.hooksPath /dev/null
    set_cfg core.fsmonitor false
    set_cfg core.attributesFile /dev/null
    set_cfg gc.auto 0
    set_cfg remote.origin.url "$2"
    [ -n "$fmt" ] && set_cfg extensions.objectformat "$fmt"
    [ -n "$refs" ] && set_cfg extensions.refstorage "$refs"
    if [ -n "$pfilter" ]; then
        set_cfg remote.origin.promisor true
        set_cfg remote.origin.partialclonefilter "$pfilter"
        set_cfg extensions.partialclone origin
    fi
    rm -f "$1/commondir" "$1/config.worktree"
    mv -f "$w_new" "$w_old"
}

# --- refresh-seed mode (the owner's seed-refresh task, never a workspace) -------------

refresh_one() {
    idx=$1; key=$2; url=$3; ckind=$4; cenv=$5
    case "$ckind" in pat|ssh) valid_cred_name "$cenv" || ckind=none ;; *) ckind=none ;; esac
    if [ "$(seed_key "$url")" != "$key" ]; then
        log "seed record $idx: key does not match its url, skipping"
        failed=$((failed + 1))
        return 0
    fi
    sb="$SEEDS/$key.git"
    if [ -e "$sb" ] || [ -L "$sb" ]; then
        if plain_bare "$sb" && write_bare_config "$sb" "$url"; then
            if ! git_fetch_into "$sb" 'refs/heads/*'; then
                log "$key: fetch failed, keeping the previous mirror"
                failed=$((failed + 1))
                printf '%s\n' "$key" >> "$PRIV/keep"
                return 0
            fi
        else
            log "$key: not a plain bare repository, recloning"
            rm -rf "$sb"
        fi
    fi
    if [ ! -d "$sb" ]; then
        new="$SEEDS/.new/$idx"
        rm -rf "$new"
        if ! { mkdir -p "$SEEDS/.new" "${sb%/*}" && git_clone "$url" "$ckind" "$cenv" "$new" -q --bare \
            && write_bare_config "$new" "$url" && mv "$new" "$sb"; }; then
            log "$key: clone failed"
            rm -rf "$new"
            failed=$((failed + 1))
            return 0
        fi
    fi
    git_local --git-dir="$sb" -c gc.auto=6700 -c gc.autoDetach=false gc --auto --quiet || true
    printf '%s\n' "$key" >> "$PRIV/keep"
    log "$key: mirror up to date"
}

refresh_seed() {
    # Only seed-refresh tasks ever mount this volume: anything but the seed is dropped.
    for e in "$ROOT"/* "$ROOT"/.[!.]* "$ROOT"/..?*; do
        [ -e "$e" ] || [ -L "$e" ] || continue
        case "${e##*/}" in .warren-bares|lost+found) ;; *) rm -rf "$e" ;; esac
    done
    if [ -L "$SEEDS" ] || [ -n "$(find "$SEEDS" -type l -print 2>/dev/null | head -n 1)" ]; then
        log "the seed holds symlinks; starting it over"
        rm -rf "$SEEDS"
    fi
    { mkdir -p "$SEEDS" && [ -w "$SEEDS" ]; } || not_writable "$SEEDS"
    : > "$PRIV/keep"
    failed=0
    each_seed refresh_one
    rm -rf "$PRIV/creds" "$SEEDS/.new"
    # Drop every mirror that wasn't listed, then anything that isn't a mirror.
    find "$SEEDS" -mindepth 1 -type d -name '*.git' -prune -print | while IFS= read -r d; do
        rel=${d#"$SEEDS"/}
        grep -qxF -- "${rel%.git}" "$PRIV/keep" || { rm -rf "$d"; log "${rel%.git}: dropped from the seed"; }
    done
    find "$SEEDS" -mindepth 1 \( -type d -name '*.git' -prune \) -o \( ! -type d -print \) \
        | while IFS= read -r f; do rm -f "$f"; done
    # Empty directories left between mirrors (never inside one), innermost first.
    n=0
    while [ "$n" -lt 64 ]; do
        empties=$(find "$SEEDS" -mindepth 1 \( -type d -name '*.git' -prune \) -o \( -type d -empty -print \))
        [ -n "$empties" ] || break
        printf '%s\n' "$empties" | while IFS= read -r e; do rmdir "$e" 2>/dev/null; done
        n=$((n + 1))
    done
    log "seed refreshed ($failed failed)"
    [ "$failed" = 0 ] || exit 3
    exit 0
}

if [ "$MODE" = refresh-seed ]; then
    refresh_seed
fi

# --- materialize mode (the workspace's git-init) --------------------------------------

# Whether the volume is exactly what an owner's seed snapshot restores: the seed and
# ext4's lost+found, nothing else, no symlinks. Anything more means something other than
# the seed-refresh task has written it, and the seed is not used.
pristine_seed_volume() {
    [ -d "$SEEDS" ] && [ ! -L "$SEEDS" ] || return 1
    for e in "$ROOT"/* "$ROOT"/.[!.]* "$ROOT"/..?*; do
        [ -e "$e" ] || [ -L "$e" ] || continue
        case "${e##*/}" in .warren-bares|lost+found) ;; *) return 1 ;; esac
    done
    [ -z "$(find "$SEEDS" -type l -print 2>/dev/null | head -n 1)" ]
}

use_seed=
if [ "$SEEDED" = 1 ] && pristine_seed_volume; then
    use_seed=1
elif [ -e "$SEEDS" ] || [ -L "$SEEDS" ]; then
    [ "$SEEDED" = 1 ] && log "the volume holds more than its seed; not using the seed"
    rm -rf "$SEEDS"
fi
rm -rf "$STAGE"

for d in "$WS_DIR" "$STORE"; do
    if [ -L "$d" ] || ! mkdir -p "$d" 2>/dev/null || [ ! -w "$d" ]; then
        not_writable "$d"
    fi
done

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

# Sets sb to this folder's seed bare when it is safe to clone from (its config rewritten);
# a seed bare that looks wrong is deleted, and the folder is cloned over the network.
seed_bare() {
    sb=
    [ -n "$use_seed" ] || return 1
    key=$(seed_key "$url") || return 1
    cand="$SEEDS/$key.git"
    [ -e "$cand" ] || [ -L "$cand" ] || return 1
    s_url=$(git_env git config --file "$cand/config" --get remote.origin.url 2>/dev/null)
    if ! plain_bare "$cand" || [ "$(seed_key "$s_url")" != "$key" ] || ! write_bare_config "$cand" "$url" \
        || [ "$(git_local --git-dir="$cand" rev-parse --is-bare-repository 2>/dev/null)" != true ]; then
        log "$name: the seed for $key is not a plain bare mirror of its url; not using it"
        rm -rf "$cand"
        return 1
    fi
    sb=$cand
}

# Clone the folder from its seed bare into $STAGE/<idx> (same filesystem: objects are
# hardlinked), then fetch only what the seed is missing, with the credentials.
seed_fetch() {
    dest="$STAGE/$idx"
    rm -rf "$dest"
    mkdir -p "$STAGE" || return 1
    if [ "$1" = clone ]; then
        git_local -c protocol.file.allow=always clone -q --local --no-checkout -- "$sb" "$dest" &&
            git_local -C "$dest" remote set-url origin "$url" &&
            git_fetch_into "$dest" 'refs/remotes/origin/*' &&
            git_local -C "$dest" rev-parse -q --verify "refs/remotes/origin/$branch^{commit}" >/dev/null &&
            git_local -C "$dest" update-ref "refs/heads/$branch" "refs/remotes/origin/$branch" &&
            git_local -C "$dest" symbolic-ref HEAD "refs/heads/$branch" &&
            git_local -C "$dest" config "branch.$branch.remote" origin &&
            git_local -C "$dest" config "branch.$branch.merge" "refs/heads/$branch" || return 1
        # Like a network clone of $branch: no other local branch.
        git_local -C "$dest" for-each-ref --format='%(refname)' refs/heads/ | while IFS= read -r r; do
            [ "$r" = "refs/heads/$branch" ] || git_local -C "$dest" update-ref -d "$r"
        done
    else
        git_local -c protocol.file.allow=always clone -q --bare --local -- "$sb" "$dest" &&
            git_fetch_into "$dest" 'refs/heads/*' &&
            git_local -C "$dest" rev-parse -q --verify "refs/heads/$branch^{commit}" >/dev/null || return 1
    fi
    log "$name: cloned from the seed, fetched what it was missing"
}

fetch() {
    idx=$1; shift
    precheck "$@" || return 0
    url=$4; branch=$5
    if [ "$1" = worktree ] && [ -d "$bare" ]; then
        return 0
    fi
    if seed_bare; then
        seed_fetch "$1" && return 0
        rm -rf "${STAGE:?}/$idx"
        log "$2: seeded clone failed, cloning over the network"
    fi
    filter=
    [ -n "$CLONE_FILTER" ] && filter="--filter=$CLONE_FILTER"
    if [ "$1" = clone ]; then
        # shellcheck disable=SC2086
        git_clone "$url" "$ckind" "$cenv" "$PRIV/$idx" --no-checkout --branch "$branch" $filter &&
            prefetch_blobs "$PRIV/$idx" HEAD
    else
        # shellcheck disable=SC2086
        git_clone "$url" "$ckind" "$cenv" "$PRIV/$idx" --bare $filter &&
            prefetch_blobs "$PRIV/$idx" "refs/heads/$branch"
    fi || {
        rm -rf "${PRIV:?}/$idx"
        if is_ssh "$url"; then
            log "$2: clone failed (an ssh host key not in $PINNED_KNOWN_HOSTS or WARREN_GIT_KNOWN_HOSTS is rejected)"
        else
            log "$2: clone failed"
        fi
    }
}

# An agent-writable bare store: rewrite its config before any git runs on it.
sanitize_store() {
    if [ -L "$bare" ] || [ -L "$bare/config" ] || [ ! -f "$bare/config" ] || [ ! -f "$bare/HEAD" ]; then
        log "$name: $bare is not a bare repository"
        return 1
    fi
    write_bare_config "$bare" "$url"
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
    [ -d "$src" ] || src="$STAGE/$idx"
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
# The seed served its purpose: its objects live on in the checkouts as hardlinks, and the
# workspace (and its snapshots) never hold the owner's other mirrors.
rm -rf "$SEEDS" "$STAGE"
log "done ($failed failed)"
exit 0
