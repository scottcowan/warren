"""The warren shell's harness commands (AG2a) and reconnect handling (AG4).

A user workspace always starts at the warren shell. Each harness the template
selects becomes a shell function that runs it with its profile's `launch_args`
and `env` (AG1); exiting it returns to the shell. `warren resume [<harness>]`
continues that harness's last conversation in this workspace by session id.

While a harness runs, `<harness root>/.session/active.json` records
`{harness, session_id, cwd, started_at}` (plus the shell's pid and host); a
normal exit clears it and keeps the session id as that harness's last. A
connect that finds the record with its shell gone (task relaunched, terminal
closed) relaunches the harness on that conversation. Session ids are read from
the harness's own session store (`HarnessProfile.session_store`).

`render()` produces `assets/warren_harness.sh` from the profiles. The same file
is written into local workspaces on connect and baked into the server images
at /etc/warren/harness.sh, so it is checked in (a test keeps it in sync). It
reads WARREN_HARNESSES, WARREN_HARNESS_ROOT and WARREN_HARNESS_DEFAULT at shell
start, and runs `_warren_on_connect` when WARREN_CONNECT=1.
"""
from __future__ import annotations

import importlib.resources
import shlex
from collections.abc import Iterable

from warren_common import agent_state
from warren_common.harness import (
    PROFILES,
    SERVER_HARNESS_ROOT,
    SESSION_DIR,
    HarnessProfile,
    _command_name,
    check_persist,
    credential_names,
    harness_dirs,
    harness_env,
    selected_harnesses,
    state_hook_env,
)

SHELLS = ("bash", "zsh", "sh")
HARNESS_SH_PATH = "/etc/warren/harness.sh"
ASSET_NAME = "warren_harness.sh"
INIT_ASSET_NAME = "warren_harness_init.sh"


def workspace_shell(app: str) -> str:
    """The warren shell for a template: `app` when it is a shell, else bash."""
    name = _command_name(app or "")
    return name if name in SHELLS else "bash"


def _app_harness(app: str) -> str | None:
    cmd = _command_name(app or "")
    for p in _selectable():
        if cmd in p.command:
            return p.name
    return None


def shell_first(app: str, mode: str = "interactive") -> bool:
    """AG2a: an interactive workspace whose app is a shell or a known harness
    starts at the warren shell. Single-turn runs, and an `app` that is neither
    (a service such as an ACP server), still run the app itself."""
    if mode == "single-turn":
        return False
    return not (app or "").strip() or _command_name(app) in SHELLS or _app_harness(app) is not None


def default_harness(app: str, harnesses: Iterable[str]) -> str:
    """The harness `--harness`/`warren resume` default to: `app`'s, else the first selected."""
    names = sorted(n for n in selected_harnesses(app or "", harnesses) if n in _selectable_names())
    own = _app_harness(app)
    if own in names:
        return own
    return names[0] if names else ""


def session_env(names: Iterable[str], root: str, *, app: str = "") -> dict[str, str]:
    """Env the shell's harness commands read."""
    selected = sorted(n for n in names if n in _selectable_names())
    if not selected:
        return {}
    env = {
        "WARREN_HARNESSES": " ".join(selected),
        "WARREN_HARNESS_ROOT": root.rstrip("/"),
        "WARREN_HARNESS_DEFAULT": default_harness(app, selected),
    }
    # Server images find the hook at its fixed path (harness.sh), keeping RunTask env small.
    if root.rstrip("/") != SERVER_HARNESS_ROOT and any(PROFILES[n].state_hook for n in selected):
        env["WARREN_STATE_HOOK"] = state_hook_env(root)["WARREN_STATE_HOOK"]
    return env


def seed_env(app: str, harnesses: Iterable[str], seed_prompt: str | None) -> dict[str, str]:
    """The template's seed_prompt for the default harness's first run, where it
    takes the prompt as its first argument (warren_common.seed_prompt)."""
    from warren_common.seed_prompt import seed_prompt_args  # noqa: PLC0415

    default = default_harness(app, harnesses)
    if seed_prompt and default and seed_prompt_args(default, seed_prompt) == [seed_prompt]:
        return {"WARREN_SEED_PROMPT": seed_prompt}
    return {}


def server_env(names: Iterable[str], *, app: str = "", mode: str = "interactive") -> dict[str, str]:
    """Env a server workspace (podman/ECS) gets for its harnesses: just their names.
    The profile data (dirs, persist paths, generated config, launch flags) is baked
    into the image's /etc/warren/harness.sh and warren-harness-init, keeping ECS
    RunTask overrides small. An app that runs as PID 1 instead of the shell gets
    the config-dir and lockdown env directly."""
    env = session_env(names, SERVER_HARNESS_ROOT, app=app)
    if not shell_first(app, mode):
        env.update(harness_env(names, SERVER_HARNESS_ROOT))
    return env


def valid_harness_name(name: str) -> bool:
    return name in _selectable_names()


def connect_env(harness: str | None = None, *, new: bool = False) -> dict[str, str]:
    """What `warren connect [--harness <name>] [--new]` asks the shell to do."""
    env = {"WARREN_CONNECT": "1"}
    if harness:
        env["WARREN_CONNECT_HARNESS"] = harness
    if new:
        env["WARREN_CONNECT_NEW"] = "1"
    return env


# `sh -c` body for podman/ECS connect: $1 shell, $2 harness or "-", $3 "new" or "-".
# Attaches to tmux session `main` (reattaching a harness still running there), or
# creates it with the warren shell. --harness/--new on a live session open a window.
TMUX_SESSION_SCRIPT = """\
s=$1; h=$2; n=$3
case "$s" in bash|zsh|sh) ;; *) s=bash ;; esac
case "$h" in -|[a-z0-9]*) ;; *) h=- ;; esac
case "$h" in *[!a-z0-9-]*) h=- ;; esac
set -- -e WARREN_CONNECT=1
[ "$h" = - ] || set -- "$@" -e "WARREN_CONNECT_HARNESS=$h"
[ "$n" != new ] || set -- "$@" -e WARREN_CONNECT_NEW=1
if { [ "$h" != - ] || [ "$n" = new ]; } && tmux has-session -t main 2>/dev/null; then
  exec tmux new-window -t main "$@" "$s" \\; attach-session -t main
fi
exec tmux new-session -A -s main "$@" "$s"
"""


def _selectable() -> list[HarnessProfile]:
    return [p for p in PROFILES.values() if p.selectable and p.kind == "harness"]


def _selectable_names() -> set[str]:
    return {p.name for p in _selectable()}


def _q(arg: str) -> str:
    return shlex.quote(arg)


def _args(args: Iterable[str]) -> str:
    return " ".join('"$_id"' if a == "{id}" else _q(a) for a in args)


def _join(base: str, rel: str) -> str:
    rel = rel.rstrip("/")
    return base if rel in ("", ".") else f"{base}/{rel}"


def _exec_case(p: HarnessProfile) -> str:
    lines = [f"    {p.name})", '      case "$_m" in']
    if p.resume_args:
        lines.append(f'        last) set -- {_args(p.resume_args)} "$@" ;;')
    if p.resume_by_id_args:
        lines.append(f'        id) set -- {_args(p.resume_by_id_args)} "$@" ;;')
    lines.append("      esac")
    if p.launch_args:
        lines.append(f'      set -- {_args(p.launch_args)} "$@"')
    if len(p.command) > 1:
        first, *rest = p.command
        lines.append(f"      _b={_q(rest[-1])}")
        lines.append(f"      _warren_inpath {_q(first)} && _b={_q(first)}")
    else:
        lines.append(f"      _b={_q(p.command[0])}")
    env = [f'{var}="{_join(f"$WARREN_HARNESS_ROOT/{p.name}", rel)}"' for var, rel in p.config_env.items()]
    env += [f"{k}={_q(v)}" for k, v in p.env.items()]
    if p.state_hook is not None:
        env.append(f'WARREN_STATE_DIR="$WARREN_HARNESS_ROOT/{SESSION_DIR}"')
    lines.append(f'      env {" ".join([*env, ""])}"$_b" "$@"')
    lines.append("      ;;")
    return "\n".join(lines)


def _sid_case(p: HarnessProfile) -> str:
    rel, glob, sed = p.session_store
    return (
        f"    {p.name}) _warren_newest \"$WARREN_HARNESS_ROOT/{p.name}/{rel}\" {_q(glob)} \"$2\""
        f" | sed -n -e 's|.*/||' -e {_q(sed)} ;;"
    )


def _prior_case(p: HarnessProfile) -> str:
    rel = p.session_cwd_dir.replace("{slug}", "$(_warren_slug)")
    return f'    {p.name}) _warren_nonempty "$WARREN_HARNESS_ROOT/{p.name}/{rel}" && return 0 ;;'


def _export_case(p: HarnessProfile) -> str:
    env = [f'{var}="{_join(f"$WARREN_HARNESS_ROOT/{p.name}", rel)}"' for var, rel in p.config_env.items()]
    env += [f"{k}={_q(v)}" for k, v in p.env.items()]
    return f"    {p.name}) export {' '.join(env)} ;;" if env else f"    {p.name}) ;;"


def _can_patterns(mode: str, attr: str) -> str:
    names = [p.name for p in _selectable() if getattr(p, attr)]
    return "|".join(f"{n}:{mode}" for n in names) or f"_none:{mode}"


def render() -> str:
    profiles = sorted(_selectable(), key=lambda p: p.name)
    return (
        _TEMPLATE.replace("@KNOWN@", "|".join(p.name for p in profiles))
        .replace("@EXEC_CASES@", "\n".join(_exec_case(p) for p in profiles))
        .replace("@CAN_LAST@", _can_patterns("last", "resume_args"))
        .replace("@CAN_ID@", _can_patterns("id", "resume_by_id_args"))
        .replace("@SID_CASES@", "\n".join(_sid_case(p) for p in profiles if p.session_store))
        .replace("@PRIOR_CASES@", "\n".join(_prior_case(p) for p in profiles if p.session_cwd_dir))
        .replace("@EXPORT_CASES@", "\n".join(_export_case(p) for p in profiles))
        .replace("@SERVER_ROOT@", SERVER_HARNESS_ROOT)
        .replace("@SERVER_HOOK@", agent_state.SERVER_HOOK_PATH)
    )


def _generate_case(p: HarnessProfile) -> str:
    lines = [f"    {p.name})"]
    for rel, text in p.generated.items():
        persisted = {e.rstrip("/") for e in p.persist}
        assert rel.split("/")[0] not in persisted, f"{p.name}: generated {rel} is under a persist path"
        if p.onboarding_version and p.onboarding_version[0] == rel:
            body = text.rstrip()
            assert body.endswith("}")
            key = p.onboarding_version[1]
            lines.append(f"      _v=$(_version {_q(p.command[0])})")
            lines.append(f"      _c={_q(body[:-1])}")
            lines.append(f'      [ -z "$_v" ] || _c="$_c, \\"{key}\\": \\"$_v\\""')
            lines.append(f'      _write "$1/{rel}" "$_c}}"')
        else:
            lines.append(f'      _write "$1/{rel}" {_q(text)}')
    if p.state_hook is not None:
        for rel, text in p.state_hook.files.items():
            lines.append(f'      _write "$1/{rel}" {_q(text)}')
    lines.append("      ;;")
    return "\n".join(lines)


def render_init() -> str:
    profiles = sorted(_selectable(), key=lambda p: p.name)
    for p in profiles:
        check_persist(p)
    keep = "|".join(f"{p.name}/{e.rstrip('/')}" for p in profiles for e in p.persist) or "_none"
    dirs = []
    for p in profiles:
        prefix = f"{SERVER_HARNESS_ROOT}/{p.name}/"
        rels = [d.removeprefix(prefix) for d in harness_dirs([p.name], SERVER_HARNESS_ROOT) if d.startswith(prefix)]
        dirs.append(f"    {p.name}) echo {_q(' '.join(rels))} ;;" if rels else f"    {p.name}) ;;")
    creds = " -o ".join(f"-name {_q(c)}" for c in credential_names())
    return (
        _INIT_TEMPLATE.replace("@KNOWN@", "|".join(p.name for p in profiles))
        .replace("@KEEP@", keep)
        .replace("@DIRS_CASES@", "\n".join(dirs))
        .replace("@CREDS@", creds)
        .replace("@GENERATE_CASES@", "\n".join(_generate_case(p) for p in profiles if p.generated or p.state_hook))
        .replace("@SESSION_DIR@", SESSION_DIR)
    )


def asset_text(name: str = ASSET_NAME) -> str:
    return importlib.resources.files("warren_common").joinpath(f"assets/{name}").read_text(encoding="utf-8")


def write_assets() -> None:
    """Regenerate the checked-in assets from the profiles."""
    assets = importlib.resources.files("warren_common").joinpath("assets")
    for name, text in ((ASSET_NAME, render()), (INIT_ASSET_NAME, render_init())):
        with open(str(assets.joinpath(name)), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)


_TEMPLATE = r"""# warren harness commands (AG2a, AG4). Generated by warren_common.harness_shell.render()
# from the harness profiles; do not edit by hand. Sourced by the warren shell (bash or
# zsh); does nothing unless WARREN_HARNESSES is set.

# Server images: an exec session may not carry the container env.
if [ -z "$WARREN_HARNESSES" ] && [ -r /etc/warren/session.env ]; then
  . /etc/warren/session.env
fi

_warren_known() {
  case "$1" in
    @KNOWN@) return 0 ;;
  esac
  return 1
}

_warren_selected() {
  _warren_known "$1" || return 1
  case " $WARREN_HARNESSES " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

_warren_can() {
  case "$1:$2" in
    @CAN_LAST@) return 0 ;;
    @CAN_ID@) return 0 ;;
  esac
  return 1
}

_warren_inpath() {
  local _p
  for _p in $(printf '%s' "$PATH" | tr ':' '\n'); do
    [ -x "$_p/$1" ] && return 0
  done
  return 1
}

# <harness> <plain|last|id> <session id> [args...]
_warren_exec() {
  local _n="$1" _m="$2" _id="$3" _b
  shift 3
  case "$_n" in
@EXEC_CASES@
    *) return 2 ;;
  esac
}

# Newest file under <dir> named <glob> modified after <marker>.
_warren_newest() {
  find "$1" -type f -name "$2" ! -path '*/subagents/*' -newer "$3" 2>/dev/null | {
    _wn=""
    while IFS= read -r _wf; do
      if [ -z "$_wn" ] || [ "$_wf" -nt "$_wn" ]; then _wn="$_wf"; fi
    done
    [ -z "$_wn" ] || printf '%s\n' "$_wn"
  }
}

# <harness> <marker>: id of the session the harness is on: its state hook's report
# (AG5) first, else the session it wrote to since <marker>.
_warren_sid() {
  local _hs=""
  if [ -f "$WARREN_HARNESS_ROOT/.session/$1.sid" ] && [ ! -L "$WARREN_HARNESS_ROOT/.session/$1.sid" ]; then
    IFS= read -r _hs < "$WARREN_HARNESS_ROOT/.session/$1.sid"
    _warren_valid_id "$_hs" && return 0
  fi
  case "$1" in
@SID_CASES@
  esac
}

_warren_valid_id() {
  case "$1" in
    ''|*[!A-Za-z0-9._-]*) return 1 ;;
  esac
  printf '%s\n' "$1"
}

_warren_slug() {
  printf '%s' "$PWD" | sed 's/[^A-Za-z0-9]/-/g'
}

_warren_nonempty() {
  [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ]
}

# <harness>: whether it has a conversation for this directory.
_warren_has_prior() {
  local _sid="" _cwd=""
  if [ -r "$WARREN_HARNESS_ROOT/.session/$1.last" ]; then
    { IFS= read -r _sid; IFS= read -r _cwd; } < "$WARREN_HARNESS_ROOT/.session/$1.last"
    [ "$_cwd" = "$PWD" ] && return 0
  fi
  case "$1" in
@PRIOR_CASES@
  esac
  return 1
}

_warren_jesc() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# <file> <key>: a value from the active.json this script writes.
_warren_json() {
  sed -n "s/^  \"$2\": \"\(.*\)\",\{0,1\}\$/\1/p" "$1" 2>/dev/null | head -n 1 \
    | sed -e 's/\\"/"/g' -e 's/\\\\/\\/g'
}

_warren_last_used() {
  local _l=""
  [ -r "$WARREN_HARNESS_ROOT/.session/last" ] && IFS= read -r _l < "$WARREN_HARNESS_ROOT/.session/last"
  _warren_selected "$_l" && printf '%s\n' "$_l"
}

# <dir> <command...>: run it in <dir> when that's where the conversation was.
_warren_in() {
  local _cwd="$1"
  shift
  if [ -n "$_cwd" ] && [ "$_cwd" != "$PWD" ] && [ -d "$_cwd" ]; then
    printf 'warren: (in %s)\n' "$_cwd"
    (cd "$_cwd" && "$@")
  else
    "$@"
  fi
}

# <harness> <plain|last|id> <session id> [args...]
_warren_run() {
  local _n="$1" _m="$2" _id="$3" _d="$WARREN_HARNESS_ROOT/.session" _rc _sid _cwd="$PWD"
  shift 3
  if mkdir -p "$_d" 2>/dev/null; then
    printf '%s\n' "$_n" > "$_d/last"
    rm -f "$_d/$_n.sid"
    : > "$_d/active.marker"
    printf '{\n  "harness": "%s",\n  "session_id": "%s",\n  "cwd": "%s",\n  "started_at": "%s",\n  "pid": "%s",\n  "host": "%s"\n}\n' \
      "$_n" "$_id" "$(_warren_jesc "$_cwd")" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$" "$(uname -n)" \
      > "$_d/active.json"
  fi 2>/dev/null
  _warren_exec "$_n" "$_m" "$_id" "$@"
  _rc=$?
  _sid=$(_warren_valid_id "$(_warren_sid "$_n" "$_d/active.marker")") || _sid="$_id"
  [ -z "$_sid" ] || printf '%s\n%s\n' "$_sid" "$_cwd" > "$_d/$_n.last" 2>/dev/null
  rm -f "$_d/active.json" "$_d/active.marker"
  [ "$_rc" -eq 127 ] && printf 'warren: %s is not installed in this workspace\n' "$_n" >&2
  return "$_rc"
}

_warren_start() {
  local _n="$1"
  if ! _warren_selected "$_n"; then
    printf 'warren: %s is not one of this workspace'"'"'s harnesses (%s)\n' "$_n" "$WARREN_HARNESSES" >&2
    return 2
  fi
  shift
  _warren_run "$_n" plain "" "$@"
}

_warren_resume() {
  local _n="$1"
  [ "$#" -gt 0 ] && shift
  [ -n "$_n" ] || _n=$(_warren_last_used)
  [ -n "$_n" ] || _n="$WARREN_HARNESS_DEFAULT"
  if ! _warren_selected "$_n"; then
    printf 'warren: %s is not one of this workspace'"'"'s harnesses (%s)\n' "${_n:-?}" "$WARREN_HARNESSES" >&2
    return 2
  fi
  local _sid="" _cwd=""
  if [ -r "$WARREN_HARNESS_ROOT/.session/$_n.last" ]; then
    { IFS= read -r _sid; IFS= read -r _cwd; } < "$WARREN_HARNESS_ROOT/.session/$_n.last"
  fi
  _sid=$(_warren_valid_id "$_sid")
  if [ -n "$_sid" ] && _warren_can "$_n" id; then
    printf 'warren: resuming %s conversation %s\n' "$_n" "$_sid"
    _warren_in "$_cwd" _warren_run "$_n" id "$_sid" "$@"
  elif _warren_can "$_n" last; then
    printf 'warren: no %s conversation recorded in this workspace; resuming its latest for this directory\n' "$_n"
    _warren_run "$_n" last "" "$@"
  else
    printf 'warren: %s has no resume flag; starting a new conversation\n' "$_n"
    _warren_run "$_n" plain "" "$@"
  fi
}

_warren_list() {
  local _h _last _note
  _last=$(_warren_last_used)
  printf '  harnesses (type one to start it, exit returns here; warren resume [harness] continues):\n'
  for _h in $(printf '%s\n' "$WARREN_HARNESSES"); do
    _warren_selected "$_h" || continue
    _note=""
    [ "$_h" = "$_last" ] && _note="last used"
    _warren_has_prior "$_h" && _note="${_note:+$_note, }previous conversation here"
    printf '    %-14s %s\n' "$_h" "$_note"
  done
  printf '\n'
}

warren() {
  case "$1" in
    resume) shift; _warren_resume "$@" ;;
    harnesses) _warren_list ;;
    *)
      if [ -n "$WARREN_CLI" ]; then
        eval "$WARREN_CLI"' "$@"'
      else
        printf 'warren: only `warren resume [harness]` and `warren harnesses` work inside this workspace\n' >&2
        return 2
      fi
      ;;
  esac
}

_warren_on_connect() {
  local _want="$WARREN_CONNECT_HARNESS" _new="$WARREN_CONNECT_NEW" _seed="$WARREN_SEED_PROMPT"
  local _d="$WARREN_HARNESS_ROOT/.session"
  unset WARREN_CONNECT WARREN_CONNECT_HARNESS WARREN_CONNECT_NEW WARREN_SEED_PROMPT
  [ -n "$WARREN_HARNESSES" ] || return 0
  _warren_list
  # The template's seed_prompt starts the default harness once per workspace (AH9).
  if [ -n "$_seed" ] && [ ! -e "$_d/seeded" ] && _warren_selected "$WARREN_HARNESS_DEFAULT"; then
    mkdir -p "$_d" 2>/dev/null && : > "$_d/seeded"
    _warren_run "$WARREN_HARNESS_DEFAULT" plain "" "$_seed"
    return
  fi
  if [ -n "$_new" ]; then
    rm -f "$_d/active.json" "$_d/active.marker"
    [ -z "$_want" ] || _warren_start "$_want"
    return
  fi
  if [ -n "$_want" ]; then
    _warren_resume "$_want"
    return
  fi
  _warren_reconnect
}

# AG4: a harness that was running when the last connection ended. Still running
# (another shell holds it) -> leave it; gone -> relaunch it on that conversation.
_warren_reconnect() {
  local _d="$WARREN_HARNESS_ROOT/.session" _n _pid _host _sid _cwd
  [ -r "$_d/active.json" ] || return 0
  _n=$(_warren_json "$_d/active.json" harness)
  if ! _warren_selected "$_n"; then
    rm -f "$_d/active.json" "$_d/active.marker"
    return 0
  fi
  _pid=$(_warren_json "$_d/active.json" pid)
  _host=$(_warren_json "$_d/active.json" host)
  if [ "$_host" = "$(uname -n)" ] && [ -n "$_pid" ] && [ "$_pid" != "$$" ] && kill -0 "$_pid" 2>/dev/null; then
    printf 'warren: %s is still running in another session of this workspace\n' "$_n"
    return 0
  fi
  _cwd=$(_warren_json "$_d/active.json" cwd)
  _sid=$(_warren_valid_id "$(_warren_json "$_d/active.json" session_id)") \
    || _sid=$(_warren_valid_id "$(_warren_sid "$_n" "$_d/active.marker")") || _sid=""
  if [ -n "$_sid" ] && _warren_can "$_n" id; then
    printf 'warren: %s was running when the last connection ended; resuming conversation %s\n' "$_n" "$_sid"
    _warren_in "$_cwd" _warren_run "$_n" id "$_sid"
  elif _warren_can "$_n" last; then
    printf 'warren: %s was running when the last connection ended; no session id recorded, resuming its latest for that directory\n' "$_n"
    _warren_in "$_cwd" _warren_run "$_n" last ""
  else
    rm -f "$_d/active.json" "$_d/active.marker"
  fi
}

# Each selected harness's config dir and lockdown env (AG1/AG3), then its command.
_warren_export() {
  case "$1" in
@EXPORT_CASES@
  esac
}

if [ -n "$WARREN_HARNESSES" ]; then
  : "${WARREN_HARNESS_ROOT:=/var/lib/warren/harness}"
  if [ -z "$WARREN_STATE_HOOK" ] && [ "$WARREN_HARNESS_ROOT" = @SERVER_ROOT@ ] && [ -r @SERVER_HOOK@ ]; then
    export WARREN_STATE_HOOK=@SERVER_HOOK@
  fi
  for _warren_h in $(printf '%s\n' "$WARREN_HARNESSES"); do
    _warren_known "$_warren_h" || continue
    _warren_export "$_warren_h"
    eval "$_warren_h() { _warren_start $_warren_h \"\$@\"; }"
  done
  unset _warren_h
fi
[ "$WARREN_CONNECT" != 1 ] || _warren_on_connect
"""


_INIT_TEMPLATE = r"""#!/bin/sh
# warren-harness-init (AB1, AG3). Generated by warren_common.harness_shell.render_init()
# from the harness profiles; do not edit by hand. Run at container start as the
# workspace user, for each harness in WARREN_HARNESSES: keep only its declared persist
# paths under <root>/<harness> (conversation history) minus credential files, recreate
# its dirs, and rewrite warren's own generated config from scratch (never merged, never
# copied from the host). Never follows a link the workspace left.
set -u
root=${1:-${WARREN_HARNESS_ROOT:-/var/lib/warren/harness}}
case "$root" in
  /*) ;;
  *) echo "warren-harness-init: root must be absolute" >&2; exit 2 ;;
esac

_keep() {
  case "$1" in
    @KEEP@) return 0 ;;
  esac
  return 1
}

_dirs() {
  case "$1" in
@DIRS_CASES@
  esac
}

_version() {
  command -v "$1" >/dev/null 2>&1 || return 0
  if command -v timeout >/dev/null 2>&1; then
    timeout 5 "$1" --version 2>/dev/null
  else
    "$1" --version 2>/dev/null
  fi | sed -n 's/^[^0-9]*\([0-9][0-9]*\.[0-9][0-9.]*\).*/\1/p' | head -n 1
}

# <file> <content>: a fresh file in place of whatever is there.
_write() {
  if [ -d "$1" ] && [ ! -L "$1" ]; then rm -rf -- "$1"; fi
  mkdir -p "${1%/*}" || return 1
  _t=$(mktemp "${1%/*}/.warren.XXXXXX") || return 1
  printf '%s' "$2" > "$_t" && chmod 600 "$_t" && mv -f -- "$_t" "$1"
}

_generate() {
  case "$2" in
@GENERATE_CASES@
  esac
}

for _h in ${WARREN_HARNESSES:-}; do
  case "$_h" in
    @KNOWN@) ;;
    *) continue ;;
  esac
  _b="$root/$_h"
  if [ -L "$_b" ] || { [ -e "$_b" ] && [ ! -d "$_b" ]; }; then rm -f -- "$_b"; fi
  mkdir -p "$_b" || continue
  for _e in "$_b"/* "$_b"/.[!.]* "$_b"/..?*; do
    if [ ! -e "$_e" ] && [ ! -L "$_e" ]; then continue; fi
    _keep "$_h/${_e##*/}" || rm -rf -- "$_e"
  done
  find "$_b" -type f \( @CREDS@ \) -exec rm -f -- {} + 2>/dev/null
  for _d in $(_dirs "$_h"); do mkdir -p "$_b/$_d"; done
  _generate "$_b" "$_h"
done
mkdir -p "$root/@SESSION_DIR@"
exit 0
"""
