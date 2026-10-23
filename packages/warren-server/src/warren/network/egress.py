"""Host-network introspection for per-workspace egress byte counting (LIFE-02, D-04/D-05).

WHY sysfs veth counters instead of `podman stats`: rootless Podman cannot report container
network I/O via `podman stats` at all (there is no cgroup-level network accounting available
to an unprivileged user namespace) — the only place a byte count is observable is the
host-side veth interface's own sysfs statistics files.

CORRECTED via live node2 verification (2026-09-19, Plan 04-02 checkpoint): for rootless
bridge-mode networking, that veth does NOT live in the operator's default/root network
namespace — it lives inside Podman's private, per-user **rootless netns**
(`podman unshare --rootless-netns`), a namespace Podman itself creates to bridge the
user's containers to the host. A plain host-side `ip link show` or `/sys/class/net/<veth>`
read (the original design) silently finds nothing there. Every veth lookup and every sysfs
statistics read in this module MUST run inside `podman unshare --rootless-netns`, with
`/sys` explicitly remounted first (`mount -t sysfs sysfs /sys`) — the rootless-netns mount
namespace inherits the outer `/sys` mount, which reflects the *outer* netns's interfaces
until remounted. Confirmed live: `veth0@if2` resolves and its `tx_bytes` counter reads and
increases correctly through this path (1640 -> 3055 after generating traffic), on Podman
4.9.3 rootless/netavark on node2 — one version below 04-RESEARCH.md's assumed >=5.0 floor,
so this fix also unblocks the effective minimum-supported-version footnote for D-04.

WHY a bridge network instead of `network_mode="none"`: D-04 requires an idle-vs-busy
signal for LIFE-01's reaper. A workspace provisioned with no network at all produces a
permanently-idle reading regardless of actual activity, which is useless as a signal. A
bridge network gives every workspace a real veth pair whose byte counters move when the
workspace does anything network-bound. PodmanRuntime gives each workspace its own isolated
bridge (Finding 9), so workspaces can't reach each other over it.

D-05 SCOPE BOUNDARY (verbatim in spirit — do not weaken this invariant): this module
OBSERVES traffic and never blocks it. It reads cumulative byte COUNTS only, never packet
contents. Do not add deep packet inspection, traffic shaping, or blocking logic under this
module — that is explicitly out of scope per D-05 ("allowlist is everything, no egress is
blocked"). Any restriction/allowlisting work belongs in a different module with its own
threat-model review.

This module is deliberately isolated and swappable, per 04-RESEARCH.md's "Key insight":
it is the riskiest hand-roll in Phase 4, so it is kept small, dependency-light, and easy to
replace. This module never touches the podman-py package at all (that HTTP client cannot
read host-namespace `ip link` state) — everything here shells out to the `podman` and `ip`
CLI binaries via `subprocess.run`. It also has no structlog/FastAPI/pydantic imports;
callers are responsible for logging.

ALL FOUR PUBLIC FUNCTIONS ARE SYNCHRONOUS AND BLOCKING. Every call site must wrap them in
`asyncio.to_thread(...)` (see `04-PATTERNS.md`'s "asyncio.to_thread boundary wrap") — do not
call them bare inside an `async def`.
"""

from __future__ import annotations

import http.client
import json
import shlex
import socket
import subprocess
from pathlib import Path

# Overridable in tests via monkeypatch; production reads the real host sysfs tree.
_SYSFS_NET_ROOT = Path("/sys/class/net")

# Prefix every rootless-netns lookup with a `/sys` remount — the rootless-netns mount
# namespace inherits whichever /sys mount was active when Podman created it, which does
# not reflect this netns's own interfaces until remounted (see module docstring).
_REMOUNT_SYSFS_CMD = "mount -t sysfs sysfs /sys >/dev/null 2>&1"

# None of these calls had a timeout at all (audit 2026-10-16 #35) -- a hung `podman
# exec`/`podman unshare` could stall the whole egress-monitoring loop indefinitely.
# 10s matches this codebase's other quick-CLI-shellout convention (see e.g.
# tests/integration/test_ssh_access.py's subprocess.run(..., timeout=20) for a
# similar podman/ssh CLI call) with a bit less margin, since these calls never do
# anything as slow as establishing a new SSH session.
_SUBPROCESS_TIMEOUT = 10.0


class EgressUnavailable(RuntimeError):
    """Raised when a container's host veth or its sysfs byte counter cannot be resolved/read.

    Every subprocess failure, missing file, and parse error inside this module is re-raised
    as this single exception type (with the original exception attached as `__cause__`), so
    callers only ever need to catch one thing.
    """


def ensure_bridge_network(name: str, *, podman_binary: str = "podman") -> None:
    """Idempotently create a Podman bridge network named `name`.

    No-op (does not raise, does not create a duplicate) when the network already exists.
    """
    try:
        exists = subprocess.run(
            [podman_binary, "network", "exists", name],
            capture_output=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if exists.returncode == 0:
            return

        result = subprocess.run(
            [podman_binary, "network", "create", "--driver", "bridge", name],
            capture_output=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if result.returncode != 0:
            stderr = _decode(result.stderr)
            if "already exists" in stderr.lower():
                return
            raise EgressUnavailable(
                f"failed to create bridge network {name!r}: {stderr}"
            )
    except FileNotFoundError as e:
        raise EgressUnavailable(f"podman binary not found: {podman_binary!r}") from e
    except subprocess.CalledProcessError as e:
        raise EgressUnavailable(f"failed to create bridge network {name!r}") from e
    except subprocess.TimeoutExpired as e:
        raise EgressUnavailable(f"timed out creating bridge network {name!r}") from e


def find_host_veth(container_id: str, *, podman_binary: str = "podman") -> str:
    """Resolve the host-side veth interface name for a running container.

    Reads the container's `/sys/class/net/eth0/iflink` peer index, then matches it against
    `ip -o link show` output run inside Podman's rootless netns (`podman unshare
    --rootless-netns`) — that is where the bridge-network veth actually lives for rootless
    bridge-mode containers, not the operator's default network namespace. Raises
    `EgressUnavailable` when no interface matches the iflink index — this is the
    pasta-default case (Pitfall 1): rootless Podman's default network mode has no veth pair
    at all, so there is nothing to find.
    """
    try:
        iflink_result = subprocess.run(
            [podman_binary, "exec", container_id, "cat", "/sys/class/net/eth0/iflink"],
            capture_output=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if iflink_result.returncode != 0:
            raise EgressUnavailable(
                f"failed to read iflink for container {container_id!r}: "
                f"{_decode(iflink_result.stderr)}"
            )
        iflink = _decode(iflink_result.stdout).strip()

        link_result = subprocess.run(
            [podman_binary, "unshare", "--rootless-netns", "ip", "-o", "link", "show"],
            capture_output=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if link_result.returncode != 0:
            raise EgressUnavailable(
                f"failed to list rootless-netns links: {_decode(link_result.stderr)}"
            )
        link_text = _decode(link_result.stdout)
    except FileNotFoundError as e:
        raise EgressUnavailable(
            f"required binary not found while resolving veth for {container_id!r}"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise EgressUnavailable(
            f"timed out resolving host veth for container {container_id!r}"
        ) from e

    # CORRECTED (live node2 finding, 2026-09-19): a veth pair's `iflink` on either side
    # reports the OTHER side's own ifindex — not a value that appears as an "@ifN" suffix
    # on its own line. `ip -o link show` prints "{own_index}: {name}@if{peer_index}: ...";
    # the host-side veth we want is the line whose LEADING index equals the container's
    # reported iflink, not the line containing "@if{iflink}" as a substring (searching for
    # that substring is wrong in general — a container's own eth0 is almost always
    # ifindex 2, so nearly every veth on the host ends in "@if2" regardless of which
    # container it belongs to; matching on that trailing marker just finds the first veth
    # on the host, not the right one).
    for line in link_text.splitlines():
        try:
            leading_index, iface_field = line.split(":", 2)[:2]
        except (IndexError, ValueError):
            continue
        if leading_index.strip() != iflink:
            continue
        return iface_field.strip().split("@")[0]

    raise EgressUnavailable(
        f"no host veth found for container {container_id!r} (iflink {iflink}); "
        "this is the pasta-default case (Pitfall 1) — no veth pair exists"
    )


def read_egress_bytes(host_veth: str, *, podman_binary: str = "podman") -> int:
    """Return the cumulative tx_bytes counter for a host veth interface.

    Reads via `podman unshare --rootless-netns`, remounting `/sys` first — the veth for a
    rootless bridge-network container lives inside that netns and its statistics file is
    invisible under `_SYSFS_NET_ROOT` from the operator's own default network namespace
    (see module docstring). Raises `EgressUnavailable` (never a raw subprocess/OS exception)
    when the interface or its sysfs statistics file is missing or unreadable.
    """
    stats_path = _SYSFS_NET_ROOT / host_veth / "statistics" / "tx_bytes"
    command = f"{_REMOUNT_SYSFS_CMD}; cat {shlex.quote(str(stats_path))}"
    try:
        result = subprocess.run(
            [podman_binary, "unshare", "--rootless-netns", "sh", "-c", command],
            capture_output=True,
            timeout=_SUBPROCESS_TIMEOUT,
        )
    except FileNotFoundError as e:
        raise EgressUnavailable(f"podman binary not found: {podman_binary!r}") from e
    except subprocess.TimeoutExpired as e:
        raise EgressUnavailable(f"timed out reading tx_bytes for veth {host_veth!r}") from e

    if result.returncode != 0:
        raise EgressUnavailable(
            f"cannot read tx_bytes for veth {host_veth!r}: {_decode(result.stderr)}"
        )
    try:
        return int(_decode(result.stdout).strip())
    except ValueError as e:
        raise EgressUnavailable(
            f"unparseable tx_bytes output for veth {host_veth!r}: {_decode(result.stdout)!r}"
        ) from e


def read_container_egress_bytes(container_id: str, *, podman_binary: str = "podman") -> int:
    """Convenience wrapper: resolve the veth then read its byte counter, every call.

    Deliberately re-resolves the veth on every invocation and never caches it (Pitfall 2):
    the host-side veth name is allocated fresh on every container start/restart, so caching
    it once at provision time and reusing it later reads stale (or another container's)
    counter.

    Only valid when called from a process that genuinely owns the host's rootless netns —
    i.e. the egress shim (`scripts/egress_shim.py`), not warren-server's own container. See
    `read_container_egress_bytes_via_shim` for the call warren-server itself actually makes.
    """
    host_veth = find_host_veth(container_id, podman_binary=podman_binary)
    return read_egress_bytes(host_veth, podman_binary=podman_binary)


def read_container_egress_bytes_via_shim(
    container_id: str, socket_path: Path | str, *, timeout: float = 5.0
) -> int:
    """Read a container's egress byte count via the host-native egress shim.

    warren-server runs as a rootless container and can never genuinely own the kernel-level
    subuid range `podman unshare --rootless-netns` needs to build a second nested namespace
    layer — confirmed live on node2 (2026-09-19): `newuidmap: write to uid_map failed:
    Operation not permitted`, reproduced under every combination of --userns=host/keep-id
    and added SETUID/SETGID capabilities. That work now runs in a small native process on
    the host instead (`scripts/egress_shim.py`, run by the real host user, not nested),
    reached here over a Unix socket bind-mounted into this container the same way
    `podman.sock` already is. This is the only public function in this module that talks
    over a socket instead of shelling out to a CLI binary directly.
    """
    conn = http.client.HTTPConnection("localhost", timeout=timeout)
    conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.sock.settimeout(timeout)
        conn.sock.connect(str(socket_path))
        conn.request("GET", f"/egress/{container_id}")
        response = conn.getresponse()
        body = response.read()
        if response.status != 200:
            raise EgressUnavailable(
                f"egress shim returned HTTP {response.status} for {container_id!r}: "
                f"{_decode(body)}"
            )
        try:
            payload = json.loads(body)
            return int(payload["tx_bytes"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            raise EgressUnavailable(
                f"malformed egress shim response for {container_id!r}: {_decode(body)!r}"
            ) from e
    except OSError as e:
        raise EgressUnavailable(
            f"failed to reach egress shim at {socket_path!r}: {e}"
        ) from e
    finally:
        conn.close()


def _decode(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode(errors="replace")
    return data
