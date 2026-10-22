#!/bin/sh
# warren-state-hook (AG5): <harness> <event> [session id], hook JSON on stdin.
# Run by the hooks warren installs in each harness's read-only config. Does nothing
# unless WARREN_STATE_DIR is set (the warren shell sets it when it starts a harness).
# Writes only inside that dir, never follows a link there, never prints, always exits 0.
d=${WARREN_STATE_DIR:-}
[ -n "$d" ] && [ -d "$d" ] && [ ! -L "$d" ] || exit 0
h=${1:-}; e=${2:-}; sid=${3:-}
case "$h" in ''|*[!a-z0-9-]*) exit 0 ;; esac
case "$e" in
  SessionStart|sessionStart) s=idle ;;
  UserPromptSubmit|beforeSubmitPrompt|PreToolUse|PostToolUse|PostToolUseFailure|SubagentStart|SubagentStop|PostCompact) s=working ;;
  PermissionRequest) s=blocked ;;
  Stop|StopFailure|stop) s=idle ;;
  SessionEnd|sessionEnd) s=exited ;;
  *) exit 0 ;;
esac
if [ -z "$sid" ] && [ ! -t 0 ]; then
  sid=$(head -c 65536 2>/dev/null | tr -d '\n\r' \
    | sed -n -E 's/.*"(session_id|sessionId|conversation_id)"[[:space:]]*:[[:space:]]*"([^"]*)".*/\2/p' | head -n 1)
fi
case "$sid" in *[!A-Za-z0-9._-]*) sid= ;; esac
[ "${#sid}" -le 128 ] || sid=
ts=$(date +%s)
umask 077
_put() {
  [ -L "$d/$1" ] && rm -f -- "$d/$1"
  _t=$(mktemp "$d/.hook.XXXXXX" 2>/dev/null) || return 0
  printf '%s\n' "$2" > "$_t" && mv -f -- "$_t" "$d/$1" || rm -f -- "$_t"
}
_put state.json "{\"harness\": \"$h\", \"state\": \"$s\", \"session_id\": \"$sid\", \"event\": \"$e\", \"ts\": $ts, \"source\": \"hook\"}"
if [ -n "$sid" ]; then
  _put "$h.sid" "$sid"
  if [ -f "$d/active.json" ] && [ ! -L "$d/active.json" ] \
    && grep -q "^  \"harness\": \"$h\",\$" "$d/active.json" 2>/dev/null; then
    _put active.json "$(sed "s/^  \"session_id\": \".*\",\$/  \"session_id\": \"$sid\",/" "$d/active.json")"
  fi
fi
exit 0
