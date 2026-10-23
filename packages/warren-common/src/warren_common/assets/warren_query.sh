#!/bin/sh
# warren-query: read-only workspace queries that warren-server runs through the
# runtime's own exec channel (podman exec, ECS Exec). The orchestrator never dials
# the sidecar; this is how it gets structured data from inside a workspace.
#
#   warren-query list ROOT
#   warren-query read ROOT PATH MAX_BYTES
#   warren-query diff ROOT MAX_BYTES
#
# POSIX sh + git + coreutils/busybox only, so the same file runs on warren-docker-base
# (Debian) and warren-ecs-base (Alpine). Runs as the workspace's unprivileged user
# (warren, else nobody), never root, and never follows a symlink below ROOT. Output is
# line-oriented; file and diff bodies are base64 so they survive ECS Exec's TTY. The
# server treats all of it as untrusted.
set -u
umask 077
# Fixed PATH: this starts as root, so nothing earlier on the caller's PATH may run.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

die() {
    echo "ERR $1"
    exit "${2:-1}"
}

if [ "$(id -u)" = 0 ]; then
    if id warren >/dev/null 2>&1; then
        uid=$(id -u warren) gid=$(id -g warren)
    else
        uid=65534 gid=65534
    fi
    if [ -x /sbin/su-exec ]; then
        exec /sbin/su-exec "$uid:$gid" "$0" "$@"
    fi
    if command -v setpriv >/dev/null 2>&1; then
        exec setpriv --reuid="$uid" --regid="$gid" --clear-groups -- "$0" "$@"
    fi
    die "cannot drop privileges" 125
fi
[ "$(id -u)" != 0 ] || die "refusing to run as root" 125

export HOME=/tmp LC_ALL=C GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_OPTIONAL_LOCKS=0 GIT_TERMINAL_PROMPT=0 GIT_PAGER=cat
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_EXTERNAL_DIFF

git_() {
    git -c safe.directory='*' -c core.fsmonitor=false -c core.hooksPath=/dev/null \
        -c core.untrackedCache=false -c diff.external= "$@"
}

[ $# -ge 2 ] || die usage 2
cmd=$1
cd -P -- "$2" 2>/dev/null || die "no workspace root" 3
root=$(pwd -P)

excluded() {
    case "/$1/" in
        */.git/* | */node_modules/* | */.venv/* | */__pycache__/*) return 0 ;;
    esac
    case "/$1" in
        */.env*) return 0 ;;
    esac
    return 1
}

# A directory under root whose resolved path differs from its spelled path has a
# symlink in it.
real_dir() {
    want=$root
    [ "$1" = . ] || want="$root/$1"
    [ "$(cd -P -- "$1" 2>/dev/null && pwd -P)" = "$want" ]
}

repos() {
    find . \( -name node_modules -o -name .venv -o -name __pycache__ \) -prune \
        -o -name .git -print -prune 2>/dev/null | sed -e 's|/\.git$||' -e 's|^\./||'
}

emit_files() {
    prefix=$1
    lastdir= lastok=1
    while IFS=' ' read -r mode size name; do
        case $mode in 8???) ;; *) continue ;; esac
        path=$prefix${name#./}
        excluded "$path" && continue
        case $path in */*) dir=${path%/*} ;; *) dir=. ;; esac
        if [ "$dir" != "$lastdir" ]; then
            lastdir=$dir
            if real_dir "$dir"; then lastok=1; else lastok=0; fi
        fi
        [ "$lastok" = 1 ] && echo "F $size $path"
    done
}

do_list() {
    # Files outside every repo (find -P never follows a link; -type f skips them).
    find . -type d -exec test -e '{}/.git' \; -prune \
        -o \( -name node_modules -o -name .venv -o -name __pycache__ -o -name '.env*' \) -prune \
        -o -type f -exec stat -c '%f %s %n' -- '{}' + 2>/dev/null | emit_files ""
    repos | while IFS= read -r r; do
        p="$r/"
        [ "$r" = . ] && p=
        excluded "$r" && continue
        real_dir "$r" || continue
        git_ -C "$r" ls-files -z -co --exclude-standard 2>/dev/null \
            | (cd -- "$r" && xargs -0 -r stat -c '%f %s %n' -- 2>/dev/null) \
            | emit_files "$p"
    done
    echo "END"
}

do_read() {
    [ $# -eq 4 ] || die usage 2
    rel=$3 max=$4
    excluded "$rel" && die excluded 4
    case $rel in */*) dir=${rel%/*} ;; *) dir=. ;; esac
    [ -e "$dir" ] || [ -L "$dir" ] || die "not found" 5
    real_dir "$dir" || die symlink 6
    [ -L "$rel" ] && die symlink 6
    [ -e "$rel" ] || die "not found" 5
    [ -f "$rel" ] || die "not a regular file" 6
    [ -r "$rel" ] || die "not readable" 8
    # The listing hides gitignored paths, so a direct read refuses them too.
    d=$dir
    while :; do
        if [ -e "$d/.git" ]; then
            inner=${rel#"${d#./}"/}
            [ "$d" = . ] && inner=$rel
            git_ -C "$d" check-ignore -q -- "$inner" 2>/dev/null && die excluded 4
            break
        fi
        [ "$d" = . ] && break
        case $d in */*) d=${d%/*} ;; *) d=. ;; esac
    done
    size=$(stat -c %s -- "$rel") || die "not found" 5
    [ "$size" -le "$max" ] || {
        echo "TOOBIG $size"
        exit 7
    }
    echo "OK $size"
    head -c "$max" <"$rel" | base64
    echo "END"
}

do_diff() {
    [ $# -eq 3 ] || die usage 2
    max=$3
    repos | while IFS= read -r r; do
        excluded "$r" && continue
        real_dir "$r" || continue
        echo "REPO $r"
        git_ -C "$r" --no-pager diff --no-ext-diff --no-textconv --no-color HEAD -- 2>/dev/null \
            | head -c "$((max + 1))" | base64
        echo "ENDREPO"
    done
    echo "END"
}

case $cmd in
    list) do_list ;;
    read) do_read "$@" ;;
    diff) do_diff "$@" ;;
    *) die usage 2 ;;
esac
