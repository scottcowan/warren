#!/usr/bin/env python3
"""Phase 4 node2 host-support verification (LIFE-02, 04-RESEARCH.md Assumptions A1/A4).

RUN THIS DIRECTLY ON node2 (the real rootless-Podman deployment host), from a bare
shell. It is deliberately stdlib-only and imports nothing from `warren` — node2 runs
warren-server *inside* a container, so this script has to work standalone against the
host's own Podman/`ip` binaries, without a Python virtualenv or the warren-server
package installed.

WHY this script exists: 04-RESEARCH.md Assumption A1 ("rootless Podman's netavark
bridge exposes per-container host veth sysfs byte counters") is MEDIUM/LOW confidence
and has never been verified against node2's actual Podman/netavark version. Plan
04-05's entire idle-TTL reaper is built on top of that assumption. This script proves
(or disproves) it here, before that investment, using the same mechanism
`src/warren/network/egress.py` uses in production: shell out to `podman`/`ip`, read
`/sys/class/net/<veth>/statistics/tx_bytes`.

Usage:
    python3 scripts/verify_phase4_host_support.py

Exits 0 if every REQUIRED check (1-5) passes. Exits non-zero otherwise. Check 6
(`podman build --memory`/`--cpus` availability) is reported as PASS/WARN, never FAIL —
its absence does not block LIFE-02, it only removes plan 04-04's resource ceiling for
arbitrary Containerfile builds.

Per D-05: this script never blocks, restricts, or allowlists traffic. It only reads
byte counters and generates a small amount of outbound test traffic to prove the
counter moves. It always cleans up the probe container/network it creates, even on
failure.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_PROBE_NETWORK = "warren-egress-probe"
_PROBE_CONTAINER = "warren-egress-probe-ctr"
_PROBE_IMAGE = "docker.io/library/busybox:latest"
_SYSFS_NET_ROOT = Path("/sys/class/net")


class _CheckFailed(Exception):
    """Raised internally to short-circuit a single check; message is the FAIL reason."""


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _pass(label: str, detail: str = "") -> None:
    suffix = f" — {detail}" if detail else ""
    print(f"PASS: {label}{suffix}")


def _warn(label: str, detail: str = "") -> None:
    suffix = f" — {detail}" if detail else ""
    print(f"WARN: {label}{suffix}")


def _fail(label: str, detail: str) -> None:
    print(f"FAIL: {label} — {detail}")


def check_podman_version_and_backend() -> tuple[bool, str]:
    """Check 1: record podman --version and confirm the network backend is netavark."""
    version_result = _run(["podman", "--version"])
    if version_result.returncode != 0:
        _fail("podman --version", version_result.stderr.strip())
        return False, ""
    version = version_result.stdout.strip()

    backend_result = _run(
        ["podman", "info", "--format", "{{.Host.NetworkBackend}}"]
    )
    if backend_result.returncode != 0:
        _fail("podman info NetworkBackend", backend_result.stderr.strip())
        return False, version
    backend = backend_result.stdout.strip()

    if backend != "netavark":
        _fail(
            "network backend is netavark",
            f"found {backend!r} instead — Assumption A1 targets netavark specifically",
        )
        return False, version

    _pass("podman --version", version)
    _pass("network backend is netavark", backend)
    return True, version


def check_create_probe_network() -> bool:
    """Check 2: idempotently create the probe bridge network."""
    exists = _run(["podman", "network", "exists", _PROBE_NETWORK])
    if exists.returncode == 0:
        _pass("probe network exists (reused)", _PROBE_NETWORK)
        return True

    result = _run(
        ["podman", "network", "create", "--driver", "bridge", _PROBE_NETWORK]
    )
    if result.returncode != 0 and "already exists" not in result.stderr.lower():
        _fail("podman network create", result.stderr.strip())
        return False
    _pass("probe network created", _PROBE_NETWORK)
    return True


def check_run_probe_container() -> bool:
    """Check 3: run a throwaway container on the probe network."""
    # Tolerate a leftover container from a previous failed run.
    _run(["podman", "rm", "-f", _PROBE_CONTAINER])
    result = _run(
        [
            "podman",
            "run",
            "-d",
            "--name",
            _PROBE_CONTAINER,
            "--network",
            _PROBE_NETWORK,
            _PROBE_IMAGE,
            "sleep",
            "120",
        ]
    )
    if result.returncode != 0:
        _fail("podman run probe container", result.stderr.strip())
        return False
    _pass("probe container running", _PROBE_CONTAINER)
    return True


def check_resolve_host_veth() -> tuple[bool, str]:
    """Check 4: resolve the probe container's host-side veth via iflink matching.

    CORRECTED (live node2 finding, 2026-09-19): for rootless bridge-mode networking, the
    veth does NOT live in the operator's default network namespace — it lives inside
    Podman's private per-user rootless netns (`podman unshare --rootless-netns`). A plain
    host-side `ip -o link show` finds nothing. Route the link lookup through that netns.
    """
    iflink_result = _run(
        ["podman", "exec", _PROBE_CONTAINER, "cat", "/sys/class/net/eth0/iflink"]
    )
    if iflink_result.returncode != 0:
        _fail("read container iflink", iflink_result.stderr.strip())
        return False, ""
    iflink = iflink_result.stdout.strip()

    link_result = _run(
        ["podman", "unshare", "--rootless-netns", "ip", "-o", "link", "show"]
    )
    if link_result.returncode != 0:
        _fail("podman unshare --rootless-netns ip -o link show", link_result.stderr.strip())
        return False, ""

    # CORRECTED (live node2 finding, 2026-09-19): a veth pair's `iflink` on either side
    # reports the OTHER side's own ifindex. Match on the LEADING index of each
    # `ip -o link show` line (its own ifindex), not on an "@ifN" substring — a container's
    # own eth0 is almost always ifindex 2, so nearly every host veth ends in "@if2"
    # regardless of which container it belongs to; matching the trailing marker just finds
    # the first veth on the host, not the right one.
    for line in link_result.stdout.splitlines():
        try:
            leading_index, iface_field = line.split(":", 2)[:2]
        except (IndexError, ValueError):
            continue
        if leading_index.strip() != iflink:
            continue
        veth = iface_field.strip().split("@")[0]
        _pass("resolved host veth", veth)
        return True, veth

    _fail(
        "resolve host veth",
        "rootless bridge does not expose a host veth — Assumption A1 is WRONG, "
        "the LIFE-01 idle signal needs a different mechanism",
    )
    return False, ""


def _read_tx_bytes(veth: str) -> int | None:
    """Read tx_bytes via `podman unshare --rootless-netns`, remounting /sys first.

    CORRECTED (live node2 finding, 2026-09-19): the rootless-netns mount namespace inherits
    whichever /sys mount was active when Podman created it — that does NOT reflect this
    netns's own interfaces until /sys is explicitly remounted here.
    """
    stats_path = _SYSFS_NET_ROOT / veth / "statistics" / "tx_bytes"
    result = _run(
        [
            "podman",
            "unshare",
            "--rootless-netns",
            "sh",
            "-c",
            f"mount -t sysfs sysfs /sys >/dev/null 2>&1; cat {stats_path}",
        ]
    )
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def check_tx_bytes_increase(veth: str) -> bool:
    """Check 5: tx_bytes counter must strictly increase after generating traffic."""
    before = _read_tx_bytes(veth)
    if before is None:
        _fail("read tx_bytes (before)", f"cannot read sysfs stats for veth {veth!r}")
        return False

    # Best-effort traffic generation; either tool is sufficient to move a few bytes.
    _run(
        [
            "podman",
            "exec",
            _PROBE_CONTAINER,
            "sh",
            "-c",
            "wget -q -O /dev/null http://example.com || "
            "ping -c 3 -w 5 1.1.1.1 || true",
        ]
    )

    after = _read_tx_bytes(veth)
    if after is None:
        _fail("read tx_bytes (after)", f"cannot read sysfs stats for veth {veth!r}")
        return False

    if after <= before:
        _fail(
            "tx_bytes strictly increased",
            f"before={before} after={after} (no increase observed)",
        )
        return False

    _pass("tx_bytes strictly increased", f"before={before} after={after}")
    return True


def check_podman_build_resource_flags() -> None:
    """Check 6: report --memory/--cpus availability on `podman build --help` (WARN, not FAIL)."""
    result = _run(["podman", "build", "--help"])
    if result.returncode != 0:
        _warn("podman build --help", result.stderr.strip())
        return
    help_text = result.stdout
    has_memory = "--memory" in help_text
    has_cpus = "--cpus" in help_text
    if has_memory and has_cpus:
        _pass("podman build --memory and --cpus available")
    else:
        missing = [
            flag
            for flag, present in (("--memory", has_memory), ("--cpus", has_cpus))
            if not present
        ]
        _warn(
            "podman build resource flags",
            f"missing: {', '.join(missing)} — removes plan 04-04's build resource ceiling, "
            "does not block LIFE-02",
        )


def cleanup() -> None:
    """Always remove the probe container and network, even on failure."""
    _run(["podman", "rm", "-f", _PROBE_CONTAINER])
    _run(["podman", "network", "rm", _PROBE_NETWORK])


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify rootless Podman/netavark bridge networking exposes per-container "
            "egress byte counters via host sysfs (04-RESEARCH.md Assumption A1), and "
            "check podman build --memory/--cpus availability (Assumption A4). "
            "MUST BE RUN ON node2 (the real deployment host) from a bare shell — it "
            "does not import warren and works without the warren-server package."
        )
    )
    parser.parse_args()

    print("Phase 4 host-support verification (run this on node2)")
    print("=" * 60)

    ok = True
    try:
        version_ok, _version = check_podman_version_and_backend()
        ok = ok and version_ok
        if not version_ok:
            # Backend/version failures make every later check meaningless.
            return 1

        ok = check_create_probe_network() and ok
        ok = check_run_probe_container() and ok

        veth_ok, veth = check_resolve_host_veth()
        ok = veth_ok and ok
        if veth_ok:
            ok = check_tx_bytes_increase(veth) and ok

        check_podman_build_resource_flags()
    finally:
        cleanup()

    print("=" * 60)
    if ok:
        print("RESULT: all required checks PASSED")
        return 0
    print("RESULT: one or more required checks FAILED — see FAIL lines above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
