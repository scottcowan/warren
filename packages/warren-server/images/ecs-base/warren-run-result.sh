#!/bin/sh
# warren-run-result: a single-turn run's result, produced inside the workspace task.
#
# For an EBS-backed ECS workspace the volume is attached only to its own task, so the
# control plane can't read the checkouts the way it does on podman or EFS
# (registry/completion.py). entrypoint.sh runs `warren-run-result write <rc>` once the
# app exits, then keeps the task up for WARREN_RUN_RESULT_HOLD_SECONDS; the control
# plane reads the file over ECS Exec (`warren-run-result cat`) and destroys the task.
# `snapshot` prints the same record without an exit code (a run that timed out).
#
# Output: one `key<TAB>base64(value)` line per field. The control plane decodes and
# parses it (warren.registry.runs.parse_workspace_result); nothing here builds JSON.
# The record is reported by the workspace, so the control plane treats it as such.
#
# POSIX sh + git + coreutils only (ecs-base has no python). Runs as the warren user.
set -u

RESULT_DIR=${WARREN_RUN_RESULT_DIR:-/tmp/warren-run}
RESULT=$RESULT_DIR/result.v1
WS_DIR=${WARREN_WORKSPACE_DIR:-/var/lib/warren/workspace}
OUTPUT=${WARREN_RUN_OUTPUT:-/var/lib/warren/harness/.session/run-output.txt}
MAX_OUTPUT=65536
MAX_VERDICT=262144
MAX_GIT=131072

b64() { base64 | tr -d '\n\r'; }
field() { printf '%s\t' "$1"; printf '%s' "$2" | b64; printf '\n'; }

regular() { [ -f "$1" ] && [ ! -L "$1" ]; }

emit_all() {
    field version 1
    field exit_code "$1"
    field ended_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'output\t'
    if regular "$OUTPUT"; then tail -c "$MAX_OUTPUT" "$OUTPUT" | b64; fi
    printf '\n'
    _verdict=$WS_DIR/.warren/verdict.json
    if regular "$_verdict"; then
        printf 'verdict\t'; head -c "$MAX_VERDICT" "$_verdict" | b64; printf '\n'
    fi
    for _entry in ${WARREN_RUN_REPOS:-}; do
        _mount=${_entry%%=*}
        _base=${_entry#*=}
        [ "$_base" != "$_entry" ] || _base=""
        case "$_mount" in ''|*[!A-Za-z0-9_./-]*|*..*|/*) continue ;; esac
        case "$_base" in *[!A-Za-z0-9_./-]*|*..*) _base="" ;; esac
        emit_repo "$_mount" "$_base"
    done
}

emit_repo() {
    _wt=$WS_DIR/$1
    field repo "$1"
    if [ ! -e "$_wt/.git" ] || [ -L "$_wt" ]; then
        field repo.error "no checkout at $1"
        return
    fi
    field repo.base_branch "$2"
    field repo.head "$(g rev-parse --verify -q 'HEAD^{commit}' 2>/dev/null)"
    _br=$(g symbolic-ref -q --short HEAD 2>/dev/null || true)
    field repo.branch "$_br"
    _basec=""
    if [ -n "$2" ]; then
        for _ref in "refs/remotes/origin/$2" "refs/heads/$2"; do
            _basec=$(g merge-base HEAD "$_ref" 2>/dev/null || true)
            [ -z "$_basec" ] || break
        done
    fi
    field repo.base "$_basec"
    printf 'repo.numstat\t'
    g diff --numstat -z "${_basec:-HEAD}" 2>/dev/null | head -c "$MAX_GIT" | b64
    printf '\n'
    printf 'repo.status\t'
    g status --porcelain=v1 -z --untracked-files=all --ignore-submodules=all 2>/dev/null \
        | head -c "$MAX_GIT" | b64
    printf '\n'
    if [ -n "$_br" ]; then
        field repo.remote "$(g rev-parse -q --verify "refs/remotes/origin/$_br" 2>/dev/null || true)"
    fi
}

# The checkout's own hooks, fsmonitor and pager never run.
g() {
    GIT_TERMINAL_PROMPT=0 GIT_PAGER=cat git -C "$_wt" -c core.fsmonitor=false \
        -c core.hooksPath=/dev/null --no-optional-locks "$@"
}

case "${1:-}" in
    write)
        (umask 077 && mkdir -p "$RESULT_DIR") || exit 1
        _tmp=$RESULT.tmp.$$
        emit_all "${2:-}" > "$_tmp" && mv -f "$_tmp" "$RESULT"
        ;;
    cat)
        regular "$RESULT" || exit 3
        cat "$RESULT"
        ;;
    snapshot)
        emit_all ""
        ;;
    *)
        echo "usage: warren-run-result write <exit-code> | cat | snapshot" >&2
        exit 2
        ;;
esac
