"""Idle-TTL reaper coroutine — Plan 04-05 Task 2 (LIFE-01).

A second, independent background loop from `run_reaper` (src/warren/registry/reaper.py):
that loop reconciles registry status against the runtime's own view of a container;
this loop decides whether a *running* workspace has generated any egress traffic
recently and stops it if not. Keeping the two loops separate (D-01) means status
reconciliation and idle-stopping stay independently testable and independently
disableable — a false-positive idle-stop bug can never take down status reconciliation
and vice versa.

Design decisions (contested, recorded here deliberately):

D-01: a separate loop from `run_reaper`, not folded into it.

D-02: SSH connection presence was rejected as the idle signal. An agent sitting idle
between conversation turns still looks "alive" to sshd's `ClientAliveInterval` — a
connection-presence check would never stop a workspace whose SSH session is merely
left open, which is the common case for an interactive workspace.

D-03: egress byte volume (via `warren.network.egress.read_container_egress_bytes`,
delivered in Plan 04-01/04-02) is used instead of a harness heartbeat file. A
heartbeat file only works for harnesses that know the convention; byte deltas work
for any agent, and this loop reuses instrumentation LIFE-02 already built and
verified against live node2 hardware.

KNOWN FALSE POSITIVE (04-RESEARCH.md Security Domain table): a workspace doing
long-running local compute with no network traffic at all reads as idle and WILL be
stopped, even though it is legitimately busy. There is no way to distinguish "idle"
from "busy but silent on the network" from the host side alone. `registry.stop()` is
what makes this survivable rather than destructive: it preserves the row, the
`ssh_port`, and the event buffer, so `ensure_running()` brings the workspace straight
back on the next `/connect` — the failure mode is an interrupted process, not lost
state. `idle_ttl_seconds` is an operator-tunable knob (default 3600s) precisely
because of this tradeoff.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog

from warren.network.egress import EgressUnavailable, read_container_egress_bytes
from warren_common import agent_state as st

log = structlog.get_logger(__name__)


async def run_idle_reaper(
    registry: Any,
    *,
    poll_interval: float = 60.0,
    idle_ttl_seconds: float = 3600.0,
    idle_destroy_seconds: float | None = None,
    clock: Any = time.monotonic,
    wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    read_egress_bytes: Callable[[str], int] | None = None,
    blocked_ttl_seconds: float = 4 * 3600.0,
    hook_max_hold_seconds: float = 24 * 3600.0,
    read_agent_state: Callable[[Any], Awaitable[st.AgentState | None]] | None = None,
    client_attached: Callable[[Any], Awaitable[bool]] | None = None,
) -> None:
    """Async idle-TTL reaper loop; runs until cancelled.

    `last_seen` maps workspace_id -> (last_known_byte_count, timestamp_of_last_change),
    mirroring `run_reaper`'s `unknown_counts` state-across-polls shape. A workspace is
    first "seen" the moment this loop notices it — not at `Workspace.created_at` — so a
    server restart does not instantly stop every pre-existing workspace the moment the
    loop starts polling; the TTL clock only starts once this loop has actually observed
    the workspace at least once.

    `read_egress_bytes` defaults to the direct (nested, podman-unshare-based) reader;
    a containerized deployment should instead pass
    `functools.partial(read_container_egress_bytes_via_shim, socket_path=...)` (see
    `warren.network.egress`) — nested rootless containers can never own the subuid range
    `podman unshare --rootless-netns` needs, so the direct reader always fails there.

    AH10: a workspace this loop stopped is destroyed once it has stayed stopped for
    its template's `idle_destroy_seconds` (else `idle_destroy_seconds` here; None, the
    default, never destroys). Wall-clock, persisted in `idle_stops`, so it survives a
    restart; a reconnect clears it.

    AH2: single-turn workspaces are never idle-stopped or idle-destroyed. They end when
    their app exits, through `registry.complete_single_turn` (workspace.completed first).

    AM1: the egress rule decides when a workspace is due; the agent state its harness
    hooks report (AG5, via `registry.agent_state`) can only hold a due workspace back,
    never stop one early, and never for more than `hook_max_hold_seconds`:
    working -> held; blocked (permission wait) -> notified once, held until blocked for
    `blocked_ttl_seconds`; idle/exited -> held until no hook event for the TTL and no
    client attached; unverifiable (no report) -> the egress rule alone.
    """
    last_seen: dict[str, tuple[int, float]] = {}
    # Resolved here (not as a default arg) so tests that monkeypatch the module-level
    # `read_container_egress_bytes` name keep working without passing `read_egress_bytes`
    # explicitly — a default arg value would bind at def time and never see the patch.
    reader = read_egress_bytes if read_egress_bytes is not None else read_container_egress_bytes
    state_reader = read_agent_state if read_agent_state is not None else getattr(registry, "agent_state", None)
    attach_check = client_attached if client_attached is not None else getattr(registry, "client_attached", None)
    hooks: dict[str, _HookTrack] = {}
    # workspace_id -> hook ts of the blocked episode already notified. Outlives `hooks`
    # (cleared on stop/reprovision) so a state file still reporting that episode isn't re-notified.
    blocked_notified: dict[str, float] = {}

    while True:
        try:
            workspaces = await registry.store.list_non_terminal()

            for ws in workspaces:
                try:
                    if ws.status != "running":
                        # provisioning/stopping/unknown are not idle-stop candidates;
                        # also drop any stale tracking entry so a later "running"
                        # sighting starts a fresh timer rather than reusing stale state.
                        last_seen.pop(ws.workspace_id, None)
                        hooks.pop(ws.workspace_id, None)
                        continue

                    if not ws.container_id or _is_single_turn(ws):
                        last_seen.pop(ws.workspace_id, None)
                        hooks.pop(ws.workspace_id, None)
                        continue

                    now = clock()
                    agent = await _read_state(state_reader, ws)
                    track = _observe(hooks, ws.workspace_id, agent, now)
                    if track is not None and track.state == st.BLOCKED:
                        if blocked_notified.get(ws.workspace_id) != track.episode_ts:
                            blocked_notified[ws.workspace_id] = track.episode_ts
                            await _notify_blocked(registry, ws.workspace_id, agent)
                    elif track is not None:
                        blocked_notified.pop(ws.workspace_id, None)

                    try:
                        byte_count = await asyncio.to_thread(reader, ws.container_id)
                    except EgressUnavailable as e:
                        log.warning(
                            "idle_reaper_egress_unavailable",
                            workspace_id=ws.workspace_id,
                            error=str(e),
                        )
                        continue

                    prev = last_seen.get(ws.workspace_id)
                    if prev is None or prev[0] != byte_count:
                        # First sighting, or traffic moved: (re)start the timer now.
                        last_seen[ws.workspace_id] = (byte_count, now)
                        if track is not None:
                            track.held_since = None
                        continue

                    _, last_change_at = prev
                    idle_seconds = now - last_change_at
                    # Per-project override (ProjectConfig.idle_ttl_seconds, threaded
                    # through WorkspaceSpec and persisted on the row at provision
                    # time) wins over the operator-wide default -- e.g. an
                    # unattended ops workspace needs far longer than the default
                    # before "idle" (no egress) actually means "nobody's using it".
                    effective_ttl = (
                        ws.idle_ttl_seconds if ws.idle_ttl_seconds is not None else idle_ttl_seconds
                    )
                    if idle_seconds < effective_ttl:
                        if track is not None:
                            track.held_since = None
                        continue
                    reason = "egress_idle"
                    if track is not None:
                        attached = await _attached(attach_check, ws)
                        reason = _hook_verdict(
                            track, now, effective_ttl, blocked_ttl_seconds, hook_max_hold_seconds, attached
                        )
                        if reason is None:
                            continue
                    await registry.stop(ws.workspace_id)
                    log.info(
                        "idle_reaper_stopped",
                        workspace_id=ws.workspace_id,
                        idle_seconds=idle_seconds,
                        reason=reason,
                        agent_state=track.state if track is not None else st.UNVERIFIABLE,
                    )
                    # Discard tracking so a later restart/reconnect starts fresh.
                    last_seen.pop(ws.workspace_id, None)
                    hooks.pop(ws.workspace_id, None)
                    stopped = await registry.store.get(ws.workspace_id)
                    if stopped is not None and stopped.status == "stopped":
                        await registry.store.mark_idle_stopped(ws.workspace_id)

                except asyncio.CancelledError:
                    raise
                except Exception:
                    log.exception(
                        "idle_reaper_iteration_failed", workspace_id=ws.workspace_id
                    )

            listed = {ws.workspace_id for ws in workspaces}
            for workspace_id in [w for w in blocked_notified if w not in listed]:
                del blocked_notified[workspace_id]

            await _destroy_expired_idle_stops(registry, idle_destroy_seconds, wall_clock())

        except asyncio.CancelledError:
            log.info("idle_reaper_cancelled")
            raise
        except Exception:
            log.exception("idle_reaper_iteration_failed")

        await asyncio.sleep(poll_interval)


@dataclass
class _HookTrack:
    state: str
    ts: float
    event_at: float  # monotonic time the latest hook event was first seen
    since: float  # monotonic time the current state began
    held_since: float | None = None
    episode_ts: float = 0.0  # hook ts of the event that entered the current state


async def _attached(check: Any, ws: Any) -> bool:
    if check is None:
        return False
    try:
        return (await check(ws)) is True
    except Exception:
        log.warning("idle_reaper_client_check_failed", workspace_id=ws.workspace_id)
        return False


async def _read_state(reader: Any, ws: Any) -> st.AgentState | None:
    if reader is None:
        return None
    try:
        agent = await reader(ws)
    except Exception:
        log.warning("idle_reaper_agent_state_unavailable", workspace_id=ws.workspace_id)
        return None
    return agent if isinstance(agent, st.AgentState) and agent.state in st.STATES else None


def _observe(hooks: dict[str, _HookTrack], workspace_id: str, agent: st.AgentState | None, now: float) -> _HookTrack | None:
    """Track the reported state; every new event resets the idle clock."""
    if agent is None:
        hooks.pop(workspace_id, None)
        return None
    track = hooks.get(workspace_id)
    if track is None:
        track = hooks[workspace_id] = _HookTrack(agent.state, agent.ts, now, now, episode_ts=agent.ts)
    elif agent.ts != track.ts or agent.state != track.state:
        if agent.state != track.state:
            track.since = now
            track.episode_ts = agent.ts
        track.state, track.ts, track.event_at = agent.state, agent.ts, now
    return track


def _hook_verdict(
    track: _HookTrack, now: float, ttl: float, blocked_ttl: float, max_hold: float, attached: bool
) -> str | None:
    """Why a due workspace may stop now, or None to hold it back."""
    if track.held_since is None:
        track.held_since = now
    if now - track.held_since >= max_hold:
        return "hook_max_hold"
    if track.state == st.WORKING:
        return None
    if track.state == st.BLOCKED:
        return "blocked_ttl" if now - track.since >= blocked_ttl else None
    if attached or now - track.event_at < ttl:
        return None
    return "agent_idle"


async def _notify_blocked(registry: Any, workspace_id: str, agent: st.AgentState | None) -> None:
    log.info("idle_reaper_agent_blocked", workspace_id=workspace_id)
    store = getattr(registry, "event_store", None)
    if store is None:
        return
    event = {"type": "workspace.agent_blocked", "workspace_id": workspace_id}
    if agent is not None and agent.harness:
        event["harness"] = agent.harness
    try:
        await store.get_or_create(workspace_id).push(json.dumps(event))
    except Exception:
        log.exception("idle_reaper_notify_failed", workspace_id=workspace_id)


def _is_single_turn(ws: Any) -> bool:
    try:
        return json.loads(ws.spec_json or "{}").get("mode") == "single-turn"
    except (ValueError, AttributeError):
        return False


def _idle_destroy_ttl(ws: Any, default: float | None) -> float | None:
    try:
        value = json.loads(ws.spec_json or "{}").get("idle_destroy_seconds")
    except (ValueError, AttributeError):
        value = None
    return value if value is not None else default


async def _destroy_expired_idle_stops(registry: Any, default: float | None, now: datetime) -> None:
    for workspace_id, stopped_at in await registry.store.list_idle_stopped():
        try:
            ws = await registry.store.get(workspace_id)
            if ws is None or ws.status != "stopped":
                await registry.store.clear_idle_stopped(workspace_id)
                continue
            ttl = None if _is_single_turn(ws) else _idle_destroy_ttl(ws, default)
            if ttl is None:
                continue
            stopped_for = (now - stopped_at).total_seconds()
            if stopped_for >= ttl:
                await registry.destroy(workspace_id)
                log.info("idle_reaper_destroyed", workspace_id=workspace_id, stopped_seconds=stopped_for)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("idle_reaper_destroy_failed", workspace_id=workspace_id)
