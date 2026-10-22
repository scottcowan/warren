#!/usr/bin/env python3
"""warren-agent-supervisor (AG2b, AM3): runs an agent workspace's harness.

Standard library only: the images copy this file to
/usr/local/bin/warren-agent-supervisor. It reads the launch spec
(warren_common.agent_launch) from WARREN_AGENT_SPEC and:

- runs the harness (or its ACP adapter) as a child, never as PID 1, restarting
  it per the spec's policy with exponential backoff; every start and exit is
  appended to `<state_dir>/events.jsonl` and logged to stderr;
- serves the workspace's one ACP endpoint (JSON-RPC 2.0 NDJSON) on loopback.
  A native-ACP harness is bridged from its stdio; a TCP adapter listens on
  `inner_port` and is proxied. Lines are bounded, peers are capped, and any
  non-loopback listener in the child's process tree stops the agent for good;
- resumes by exact session id: the id the ACP traffic or the harness's state
  hook (`<harness>.sid`) last recorded is handed to the adapter, and a peer
  still connected across a restart gets its session reloaded (`session/load`);
- reports working/blocked/idle/exited to `<state_dir>/supervisor.json` for
  the control plane's state-aware reaping (AM1).
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import os
import re
import signal
import sys
import time
from pathlib import Path
from typing import Any, Callable

SPEC_ENV = "WARREN_AGENT_SPEC"
STATE_FILE = "supervisor.json"
SESSION_FILE = "agent.json"
EVENTS_FILE = "events.jsonl"
MAX_EVENTS_BYTES = 1024 * 1024
WORKING, BLOCKED, IDLE, EXITED = "working", "blocked", "idle", "exited"
EXIT_WIDE_LISTENER = 3
EXIT_BAD_SPEC = 2
_INTERNAL = "warren-"
_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_TRACKED = 4096


class SpecError(ValueError):
    pass


def is_loopback(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def load_spec(raw: str) -> dict:
    try:
        spec = json.loads(raw)
    except ValueError as exc:
        raise SpecError(f"{SPEC_ENV} is not JSON: {exc}") from exc
    if not isinstance(spec, dict) or not spec.get("argv") or not spec.get("harness"):
        raise SpecError(f"{SPEC_ENV} needs harness and argv")
    if not is_loopback(str(spec.get("host", ""))):
        raise SpecError(f"ACP endpoint host {spec.get('host')!r} is not loopback")
    if spec.get("transport", "stdio") not in ("stdio", "tcp"):
        raise SpecError(f"unknown transport {spec.get('transport')!r}")
    for key in ("port", "inner_port"):
        if not isinstance(spec.get(key), int) or not 1 <= spec[key] <= 65535:
            raise SpecError(f"{key} must be a TCP port")
    spec.setdefault("restart", {})
    spec.setdefault("resume_args", [])
    spec.setdefault("env", {})
    spec.setdefault("max_line_bytes", 4 * 1024 * 1024)
    spec["max_peers"] = 1 if spec.get("transport", "stdio") == "stdio" else max(1, int(spec.get("max_peers", 1)))
    return spec


# --- listeners of a process tree, from /proc (Linux) ---

def _proc_addr(field: str) -> tuple[str, int]:
    host, port = field.split(":")
    raw = bytes.fromhex(host)
    # /proc/net/tcp{,6} print each 32-bit word in host (little-endian) order.
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    return str(ipaddress.ip_address(raw)), int(port, 16)


def _tree(pid: int, proc: Path) -> list[int]:
    out, todo = [], [pid]
    while todo and len(out) < 1024:
        p = todo.pop()
        out.append(p)
        for children in proc.glob(f"{p}/task/*/children"):
            with contextlib.suppress(OSError, ValueError):
                todo += [int(c) for c in children.read_text().split()]
    return out


def proc_listeners(pid: int, proc: str | Path = "/proc") -> list[tuple[str, int]] | None:
    """Listening TCP sockets held by `pid` or its descendants; None without /proc."""
    proc = Path(proc)
    if not (proc / "net" / "tcp").exists():
        return None
    inodes: set[str] = set()
    for p in _tree(pid, proc):
        with contextlib.suppress(OSError):
            for fd in (proc / str(p) / "fd").iterdir():
                with contextlib.suppress(OSError):
                    target = os.readlink(fd)
                    if target.startswith("socket:["):
                        inodes.add(target[8:-1])
    found = []
    for table in ("tcp", "tcp6"):
        with contextlib.suppress(OSError):
            for row in (proc / "net" / table).read_text().splitlines()[1:]:
                cols = row.split()
                if len(cols) > 9 and cols[3] == "0A" and cols[9] in inodes:
                    found.append(_proc_addr(cols[1]))
    return found


# --- the supervisor ---

def _now() -> float:
    return time.time()


def _dump(msg: dict) -> bytes:
    return (json.dumps(msg, separators=(",", ":")) + "\n").encode()


def _error(id_: Any, code: int, message: str) -> bytes:
    return _dump({"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}})


class Channel:
    """One line stream to the agent (its stdio, or one TCP connection to an adapter)."""

    def __init__(self, sup: "Supervisor", reader: asyncio.StreamReader, writer: Any, generation: int) -> None:
        self.sup = sup
        self.reader = reader
        self.writer = writer
        self.generation = generation
        self.peer: "Peer | None" = None
        self.internal: dict[str, asyncio.Future] = {}
        self.swallow_updates = False
        self.closed = asyncio.Event()

    async def send(self, line: bytes) -> None:
        self.writer.write(line)
        await self.writer.drain()

    async def request(self, method: str, params: dict, timeout: float) -> dict:
        id_ = f"{_INTERNAL}{method}-{self.generation}"
        fut = asyncio.get_running_loop().create_future()
        self.internal[id_] = fut
        await self.send(_dump({"jsonrpc": "2.0", "id": id_, "method": method, "params": params}))
        return await asyncio.wait_for(fut, timeout)

    async def pump(self) -> None:
        try:
            while True:
                try:
                    line = await self.reader.readline()
                except (ValueError, asyncio.LimitOverrunError):
                    self.sup.record("acp.line_dropped", direction="agent", limit=self.sup.max_line)
                    await self._skip_long_line()
                    continue
                if not line:
                    break
                msg = _parse(line)
                if msg is not None and str(msg.get("id", "")).startswith(_INTERNAL) and "method" not in msg:
                    fut = self.internal.pop(str(msg["id"]), None)
                    if fut is not None and not fut.done():
                        fut.set_result(msg)
                    continue
                if self.swallow_updates and msg is not None and msg.get("method") == "session/update":
                    continue
                if msg is not None:
                    self.sup.observe_agent(self.peer, msg)
                if self.peer is not None:
                    await self.peer.deliver(line)
        except (ConnectionError, OSError):
            pass
        finally:
            for fut in self.internal.values():
                if not fut.done():
                    fut.set_exception(ConnectionError("agent channel closed"))
            self.closed.set()

    async def _skip_long_line(self) -> None:
        while True:
            try:
                await self.reader.readuntil(b"\n")
                return
            except asyncio.LimitOverrunError as exc:
                await self.reader.readexactly(exc.consumed)
            except asyncio.IncompleteReadError:
                return

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.writer.close()


def _parse(line: bytes) -> dict | None:
    try:
        msg = json.loads(line)
    except ValueError:
        return None
    return msg if isinstance(msg, dict) else None


class Peer:
    """A client connected to the ACP endpoint."""

    _seq = 0

    def __init__(self, sup: "Supervisor", reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        Peer._seq += 1
        self.key = Peer._seq
        self.sup = sup
        self.reader = reader
        self.writer = writer
        self.channel: Channel | None = None
        self.init_params: dict | None = None
        self.lock = asyncio.Lock()

    async def deliver(self, line: bytes) -> None:
        async with self.lock:
            self.writer.write(line if line.endswith(b"\n") else line + b"\n")
            with contextlib.suppress(ConnectionError, OSError):
                await self.writer.drain()

    async def run(self) -> None:
        while True:
            try:
                line = await self.reader.readline()
            except (ValueError, asyncio.LimitOverrunError):
                self.sup.record("acp.peer_line_too_long", limit=self.sup.max_line)
                await self.deliver(_error(None, -32600, f"line exceeds {self.sup.max_line} bytes"))
                return
            if not line:
                return
            if not line.strip():
                continue
            msg = _parse(line)
            if msg is None:
                await self.deliver(_error(None, -32700, "parse error"))
                continue
            if msg.get("method") == "initialize" and isinstance(msg.get("params"), dict):
                self.init_params = msg["params"]
            self.sup.observe_client(self, msg)
            try:
                channel = await self.sup.channel_for(self)
                await channel.send(line if line.endswith(b"\n") else line + b"\n")
            except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
                if "id" in msg and "method" in msg:
                    await self.deliver(_error(msg["id"], -32603, f"agent unavailable: {exc}"))


class Supervisor:
    def __init__(
        self,
        spec: dict,
        *,
        listeners: Callable[[int], list[tuple[str, int]] | None] = proc_listeners,
        listener_check_seconds: float = 2.0,
        ready_timeout: float = 60.0,
    ) -> None:
        self.spec = spec
        self.harness = spec["harness"]
        self.state_dir = Path(spec.get("state_dir") or ".")
        self.max_line = int(spec["max_line_bytes"])
        self.listeners = listeners
        self.listener_check_seconds = listener_check_seconds
        self.ready_timeout = ready_timeout
        policy = spec["restart"]
        self.policy = policy.get("policy", "on-failure")
        self.max_restarts = int(policy.get("max_restarts", 5))
        self.backoff = float(policy.get("backoff_seconds", 1.0))
        self.backoff_max = float(policy.get("backoff_max_seconds", 60.0))
        self.stable = float(policy.get("stable_seconds", 120.0))
        self.proc: asyncio.subprocess.Process | None = None
        self.generation = 0
        self.running = asyncio.Event()
        self.stdio: Channel | None = None
        self.peers: dict[int, Peer] = {}
        self.inflight: dict[tuple[int, Any], None] = {}
        self.permissions: dict[tuple[int, Any], None] = {}
        self.methods: dict[tuple[int, Any], tuple[str, dict]] = {}
        self.load_session = False
        self.session_id = ""
        self.state = ""
        self.fatal = ""
        self.stopping = False
        self.server: asyncio.base_events.Server | None = None

    # -- records --

    def record(self, event: str, **fields: Any) -> None:
        entry = {"ts": _now(), "event": event, "harness": self.harness, **fields}
        line = json.dumps(entry, separators=(",", ":"))
        print(f"warren-agent-supervisor: {line}", file=sys.stderr, flush=True)
        path = self.state_dir / EVENTS_FILE
        with contextlib.suppress(OSError):
            if path.exists() and path.stat().st_size > MAX_EVENTS_BYTES:
                os.replace(path, path.with_suffix(".jsonl.1"))
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def _put(self, name: str, obj: dict) -> None:
        path = self.state_dir / name
        tmp = self.state_dir / f".{name}.{os.getpid()}"
        with contextlib.suppress(OSError):
            if path.is_symlink():
                path.unlink()
            tmp.write_text(json.dumps(obj) + "\n", encoding="utf-8")
            os.replace(tmp, path)

    def set_state(self, state: str, event: str) -> None:
        self.state = state
        self._put(STATE_FILE, {
            "harness": self.harness, "state": state, "session_id": self.session_id,
            "event": event, "ts": _now(), "source": "supervisor",
        })

    def _settle(self, event: str) -> None:
        if self.permissions:
            self.set_state(BLOCKED, event)
        elif self.inflight:
            self.set_state(WORKING, event)
        else:
            self.set_state(IDLE, event)

    def remember_session(self, sid: Any) -> None:
        if isinstance(sid, str) and _ID.match(sid) and sid != self.session_id:
            self.session_id = sid
            self._put(SESSION_FILE, {"harness": self.harness, "session_id": sid, "ts": _now()})
            self.record("agent.session", session_id=sid)

    def recorded_session(self) -> str:
        """The newest valid id: the supervisor's own record or the state hook's `<harness>.sid`."""
        best, best_mtime = "", -1.0
        for name in (SESSION_FILE, f"{self.harness}.sid"):
            path = self.state_dir / name
            try:
                if path.is_symlink():
                    continue
                raw = path.read_text(encoding="utf-8")[:4096].strip()
                mtime = path.stat().st_mtime
            except OSError:
                continue
            if name == SESSION_FILE:
                try:
                    raw = str(json.loads(raw).get("session_id", ""))
                except (ValueError, AttributeError):
                    continue
            if _ID.match(raw) and mtime > best_mtime:
                best, best_mtime = raw, mtime
        return best

    # -- ACP observation: state and session ids --

    def _track(self, d: dict, key: tuple, value: Any) -> None:
        if len(d) >= _TRACKED:
            d.pop(next(iter(d)))
        d[key] = value

    def observe_client(self, peer: Peer, msg: dict) -> None:
        method, id_ = msg.get("method"), msg.get("id")
        if method and id_ is not None:
            self._track(self.methods, (peer.key, id_), (method, msg.get("params") or {}))
            if method == "session/prompt":
                self._track(self.inflight, (peer.key, id_), None)
                self.set_state(WORKING, "session/prompt")
        elif method is None and (peer.key, id_) in self.permissions:
            del self.permissions[(peer.key, id_)]
            self._settle("permission/answered")

    def observe_agent(self, peer: Peer | None, msg: dict) -> None:
        key = (peer.key if peer else 0, msg.get("id"))
        method = msg.get("method")
        if method == "session/request_permission" and "id" in msg:
            self._track(self.permissions, key, None)
            self.set_state(BLOCKED, method)
            return
        if method or "id" not in msg:
            return
        sent = self.methods.pop(key, None)
        result = msg.get("result") if isinstance(msg.get("result"), dict) else {}
        if sent is not None:
            name, params = sent
            if name == "initialize":
                caps = result.get("agentCapabilities") or {}
                self.load_session = bool(isinstance(caps, dict) and caps.get("loadSession"))
            elif name == "session/new":
                self.remember_session(result.get("sessionId"))
            elif name in ("session/load", "session/resume"):
                self.remember_session(params.get("sessionId") if isinstance(params, dict) else None)
        if key in self.inflight:
            del self.inflight[key]
            self._settle("session/prompt/done")

    # -- the agent's channel(s) --

    async def channel_for(self, peer: Peer) -> Channel:
        deadline = time.monotonic() + self.ready_timeout
        while True:
            if self.fatal or self.stopping:
                raise ConnectionError(self.fatal or "supervisor stopping")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError("agent not ready")
            try:
                await asyncio.wait_for(self.running.wait(), remaining)
            except asyncio.TimeoutError:
                raise asyncio.TimeoutError("agent not ready") from None
            ch = peer.channel
            if ch is not None and ch.generation == self.generation and not ch.closed.is_set():
                return ch
            ch = self.stdio if self.spec["transport"] == "stdio" else await self._connect_inner()
            if ch is None:
                await asyncio.sleep(0.05)
                continue
            fresh = peer.channel is not None
            peer.channel, ch.peer = ch, peer
            if ch is not self.stdio:
                asyncio.create_task(ch.pump())
            if fresh:
                await self._reload(peer, ch)
            return ch

    async def _connect_inner(self) -> Channel | None:
        try:
            r, w = await asyncio.open_connection(self.spec["host"], self.spec["inner_port"], limit=self.max_line)
        except OSError:
            return None
        return Channel(self, r, w, self.generation)

    async def _reload(self, peer: Peer, ch: Channel) -> None:
        """A peer that stayed connected across a restart: reopen its session by id."""
        if not (peer.init_params and self.session_id):
            return
        ch.swallow_updates = True
        try:
            init = await ch.request("initialize", peer.init_params, self.ready_timeout)
            caps = (init.get("result") or {}).get("agentCapabilities") or {}
            if not caps.get("loadSession"):
                self.record("agent.resume_unsupported", session_id=self.session_id)
                return
            cwd = os.getcwd()
            for (key, _), (name, params) in list(self.methods.items()):
                if key == peer.key and name == "session/new" and isinstance(params, dict):
                    cwd = params.get("cwd") or cwd
            res = await ch.request(
                "session/load", {"sessionId": self.session_id, "cwd": cwd, "mcpServers": []}, self.ready_timeout
            )
            self.record("agent.resumed", session_id=self.session_id, ok="error" not in res)
        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            self.record("agent.resume_failed", session_id=self.session_id, error=str(exc))
        finally:
            ch.swallow_updates = False

    # -- peers --

    async def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = Peer(self, reader, writer)
        addr = writer.get_extra_info("peername") or ("", 0)
        if not is_loopback(str(addr[0])) or len(self.peers) >= int(self.spec["max_peers"]):
            self.record("acp.peer_rejected", reason="limit" if is_loopback(str(addr[0])) else "non-loopback")
            writer.write(_error(None, -32000, "ACP endpoint busy"))
            with contextlib.suppress(Exception):
                await writer.drain()
                writer.close()
            return
        self.peers[peer.key] = peer
        self.record("acp.peer_connected", peers=len(self.peers))
        try:
            await peer.run()
        finally:
            self.peers.pop(peer.key, None)
            for d in (self.inflight, self.permissions, self.methods):
                for k in [k for k in d if k[0] == peer.key]:
                    del d[k]
            if self.stdio is not None and self.stdio.peer is peer:
                self.stdio.peer = None
            elif peer.channel is not None:
                peer.channel.close()
            with contextlib.suppress(Exception):
                writer.close()
            self.record("acp.peer_disconnected", peers=len(self.peers))
            if self.state in (WORKING, BLOCKED):
                self._settle("peer/disconnected")

    # -- the child process --

    def argv(self) -> list[str]:
        sid = self.session_id
        resume = [a.replace("{id}", sid) for a in self.spec["resume_args"]] if sid else []
        adapter = self.spec.get("adapter")
        if not adapter:
            return list(self.spec["argv"])
        values = {
            "{port}": str(self.spec["inner_port"] if self.spec["transport"] == "tcp" else self.spec["port"]),
            "{harness}": self.harness,
            "{session_id}": sid,
            "{state_dir}": str(self.state_dir),
        }
        out: list[str] = []
        for arg in adapter:
            if arg == "{harness_argv}":
                out += self.spec["argv"]
            elif arg == "{resume_argv}":
                out += resume
            else:
                for k, v in values.items():
                    arg = arg.replace(k, v)
                out.append(arg)
        return out

    def child_env(self) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if k != SPEC_ENV}
        env.update({str(k): str(v) for k, v in self.spec["env"].items()})
        env["WARREN_AGENT_PORT"] = str(self.spec["port"])
        if self.session_id:
            env["WARREN_AGENT_SESSION_ID"] = self.session_id
        return env

    async def _start_child(self) -> None:
        stdio = self.spec["transport"] == "stdio"
        argv = self.argv()
        self.proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdio else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE if stdio else None,
            env=self.child_env(),
            limit=self.max_line,
            start_new_session=True,
        )
        self.generation += 1
        self.record("agent.started", pid=self.proc.pid, argv=argv[:1], generation=self.generation,
                    session_id=self.session_id)
        if stdio:
            assert self.proc.stdout is not None and self.proc.stdin is not None
            self.stdio = Channel(self, self.proc.stdout, self.proc.stdin, self.generation)
            asyncio.create_task(self.stdio.pump())
        self.running.set()
        self._settle("agent/started")

    async def _watch_listeners(self, pid: int) -> None:
        warned = False
        while True:
            found = self.listeners(pid)
            if found is None and not warned:
                self.record("agent.listener_check_unavailable")
                warned = True
            wide = [f"{a}:{p}" for a, p in (found or []) if not is_loopback(a)]
            if wide:
                self.fatal = f"agent listens beyond loopback: {', '.join(wide)}"
                self.record("agent.listener_rejected", listeners=wide)
                self._signal_child(signal.SIGKILL)
                return
            await asyncio.sleep(self.listener_check_seconds)

    def _signal_child(self, sig: int) -> None:
        if self.proc is not None and self.proc.returncode is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.proc.pid, sig)

    async def _run_child(self) -> int:
        await self._start_child()
        assert self.proc is not None
        watch = asyncio.create_task(self._watch_listeners(self.proc.pid))
        try:
            rc = await self.proc.wait()
        finally:
            watch.cancel()
            self.running.clear()
        await self._fail_inflight()
        if self.stdio is not None:
            self.stdio.close()
        return rc if rc >= 0 else 128 - rc

    async def _fail_inflight(self) -> None:
        for (key, id_) in list(self.inflight) + list(self.permissions):
            peer = self.peers.get(key)
            if peer is not None and key and (key, id_) in self.inflight:
                await peer.deliver(_error(id_, -32603, "agent exited; restarting"))
        self.inflight.clear()
        self.permissions.clear()

    def stop(self) -> None:
        self.stopping = True
        self._signal_child(signal.SIGTERM)

    async def _sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while not self.stopping and time.monotonic() < end:
            await asyncio.sleep(min(0.1, max(0.0, end - time.monotonic())))

    async def _serve(self) -> None:
        self.server = await asyncio.start_server(
            self._accept, self.spec["host"], self.spec["port"], limit=self.max_line
        )
        for sock in self.server.sockets:
            addr = sock.getsockname()[0]
            if not is_loopback(addr):
                raise SpecError(f"ACP endpoint bound {addr}, not loopback")
        self.record("acp.listening", host=self.spec["host"], port=self.spec["port"])

    async def run(self) -> int:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = self.recorded_session()
        await self._serve()
        restarts, rc = 0, 0
        try:
            while not self.stopping:
                started = time.monotonic()
                rc = await self._run_child()
                ran = time.monotonic() - started
                self.record("agent.exited", exit_code=rc, ran_seconds=round(ran, 3), restarts=restarts)
                if self.fatal:
                    self.set_state(EXITED, "agent/rejected")
                    return EXIT_WIDE_LISTENER
                if self.stopping:
                    break
                if ran >= self.stable:
                    restarts = 0
                if self.policy == "never" or (self.policy == "on-failure" and rc == 0):
                    self.set_state(EXITED, "agent/exited")
                    return rc
                if restarts >= self.max_restarts:
                    self.record("agent.gave_up", exit_code=rc, restarts=restarts)
                    self.set_state(EXITED, "agent/gave-up")
                    return rc or 1
                delay = min(self.backoff * (2 ** restarts), self.backoff_max)
                restarts += 1
                self.set_state(WORKING, "agent/restarting")
                self.record("agent.restarting", attempt=restarts, delay_seconds=delay)
                await self._sleep(delay)
                self.session_id = self.recorded_session() or self.session_id
            self.set_state(EXITED, "supervisor/stopped")
            return 0
        finally:
            self.server.close()
            for peer in list(self.peers.values()):
                with contextlib.suppress(Exception):
                    peer.writer.close()


async def _main(spec: dict) -> int:
    sup = Supervisor(spec)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, sup.stop)
    return await sup.run()


def main() -> int:
    try:
        spec = load_spec(os.environ.get(SPEC_ENV, ""))
    except SpecError as exc:
        print(f"warren-agent-supervisor: {exc}", file=sys.stderr)
        return EXIT_BAD_SPEC
    try:
        return asyncio.run(_main(spec))
    except (SpecError, OSError) as exc:
        print(f"warren-agent-supervisor: {exc}", file=sys.stderr)
        return EXIT_BAD_SPEC


if __name__ == "__main__":
    sys.exit(main())
