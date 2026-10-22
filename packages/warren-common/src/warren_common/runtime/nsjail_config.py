"""NsjailConfig dataclass + proto-text serialiser (Plan 05-02, D-01/D-02/D-03).

Pure-data foundation with zero side-effects. `to_proto_text()` produces the
Protobuf text-format that `nsjail --config` expects.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from warren_common.harness import grants_for_spec
from warren_common.runtime.base import WorkspaceSpec
from warren_common.runtime.sandbox_env import (
    ENV_MOUNT_DEST,
    check_no_secret_service_mounts,
    host_mount_sources,
    nsjail_secret_env_path,
)


def _escape(value: str) -> str:
    """Escape a raw string for proto text: backslash first, then double-quote."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


# Audit 2026-10-16 P2 #51: a reasonable default-deny-dangerous-syscalls
# profile (allow by default, kill on syscalls with no legitimate use in a
# workspace -- the same shape as Docker's own default seccomp profile,
# translated into nsjail's kafel policy language) rather than inventing a
# strict allow-list, which is far more likely to silently break ordinary
# workspace commands (git, python, node, aws, ...) with no way to verify
# that against a live nsjail binary from this change alone (nsjail is
# Linux-only; see nsjail.py's module docstring for the verification caveat).
DEFAULT_SECCOMP_POLICY = """\
POLICY warren_default {
    KILL {
        ptrace, mount, umount2, pivot_root, reboot, swapon, swapoff,
        kexec_load, kexec_file_load, init_module, finit_module,
        delete_module, create_module, query_module, get_kernel_syms,
        acct, settimeofday, stime, clock_settime, clock_adjtime,
        sethostname, setdomainname, iopl, ioperm, modify_ldt, vm86,
        vm86old, nfsservctl, sysfs, _sysctl, syslog, uselib, ustat,
        userfaultfd, lookup_dcookie, add_key, request_key, keyctl, bpf,
        perf_event_open, process_vm_readv, process_vm_writev, personality,
        quotactl, move_pages, mbind, set_mempolicy, get_mempolicy, kcmp,
        name_to_handle_at, open_by_handle_at, vmsplice
    }
    DEFAULT ALLOW
}
USE warren_default DEFAULT ALLOW
"""


@dataclass
class MountEntry:
    dst: str
    src: Optional[str] = None
    is_bind: bool = True
    rw: bool = False
    mandatory: bool = True
    fstype: Optional[str] = None


@dataclass
class NsjailConfig:
    mode: str = "ONCE"
    hostname: str = "warren"
    cwd: str = "/workspace"
    keep_env: bool = False
    # Audit 2026-10-16 P2 #51: `clone_newnet: true` is what actually puts the
    # jailed process into a fresh, interface-less network namespace (CLONE_NEWNET)
    # -- i.e. deny network. `false` leaves it in the HOST's network namespace,
    # sharing full network access -- the exact opposite of what the old comment
    # here claimed. D-03's "default deny network" decision requires `true`.
    clone_newnet: bool = True
    # S6 follow-up (2026-10-17): P2 #51 fixed clone_newnet's inverted default
    # but never paired it with giving the now-isolated namespace any actual
    # route out -- `clone_newnet: true` alone puts the process in a netns with
    # NO interfaces at all (not even loopback-to-outside), so git/pip/the
    # Anthropic API all became unreachable. `pasta_network: true` emits an
    # nsjail `user_net { backend: PASTA ... }` block: unprivileged per-netns
    # NAT (no CAP_NET_ADMIN, no host-interface/macvlan juggling, no shared
    # L2 domain with the host or other workspaces -- each jail's PASTA
    # instance lives entirely inside its own netns and NATs outbound traffic
    # through whatever interface the host itself already uses). This is the
    # same backend rootless Podman already uses elsewhere in this project
    # (see podman.py's network_mode comments) for an identical "reach out,
    # nothing reaches in" posture -- chosen over nsjail's macvlan_* fields
    # specifically because macvlan clones a host interface into the jail and
    # needs an LAN-routable static IP per jail, which collides across
    # concurrent workspaces and needs CAP_NET_ADMIN outside the jail; PASTA
    # needs neither. UNVERIFIED on a real Linux host as of this change (see
    # nsjail.py's module docstring) -- recommend a live smoke test (DNS +
    # git fetch + an HTTPS GET) on an actual nsjail host before trusting this
    # in production.
    pasta_network: bool = True
    envar: list[str] = field(default_factory=list)
    mounts: list[MountEntry] = field(default_factory=list)
    uid_inside: int = 1000
    # Audit 2026-10-16 P2 #51: hardcoded to 1000 regardless of who is
    # actually running warren -- on any host where the operator's uid isn't
    # 1000, bind-mounted paths owned by the real uid become inaccessible
    # (wrong-owner) inside the jail. This dataclass default is left alone
    # (tests/golden fixture construct NsjailConfig directly with explicit
    # values); `from_spec()` -- the only real provisioning path -- now
    # passes the real `os.getuid()`/`os.getgid()` explicitly instead of
    # relying on this default.
    uid_outside: int = 1000
    gid_inside: int = 1000
    gid_outside: int = 1000
    rlimit_nofile: int = 4096
    rlimit_as_type: str = "SOFT"
    seccomp_string: Optional[str] = None

    def to_proto_text(self) -> str:
        b = _bool
        lines: list[str] = []
        lines.append(
            "# GENERATED-BY: NsjailConfig.to_proto_text; edit fixture inputs, not this file"
        )
        lines.append(f"mode: {self.mode}")
        lines.append(f'hostname: "{_escape(self.hostname)}"')
        lines.append(f'cwd: "{_escape(self.cwd)}"')
        lines.append(f"keep_env: {b(self.keep_env)}")
        lines.append(f"clone_newnet: {b(self.clone_newnet)}")
        if self.clone_newnet and self.pasta_network:
            # PASTA defaults already enable NAT + TCP/UDP/ICMP forwarding for
            # both IPv4 and IPv6 (nsjail's UserNet.Pasta message) -- the only
            # default worth overriding is enable_dns (false by default), so
            # the jail can resolve names through a host resolver that's a
            # loopback stub (e.g. systemd-resolved's 127.0.0.53), not just one
            # with a directly NAT-reachable upstream IP already in
            # /etc/resolv.conf (which the plain NAT path below handles on its
            # own). ns_iface/ip4/gw4 are left at nsjail's own defaults.
            lines.append("user_net {")
            lines.append("  backend: PASTA")
            lines.append("  pasta {")
            lines.append("    enable_dns: true")
            lines.append("  }")
            lines.append("}")
        if self.seccomp_string is not None:
            for seccomp_line in self.seccomp_string.splitlines():
                lines.append(f'seccomp_string: "{_escape(seccomp_line)}"')
        for e in self.envar:
            lines.append(f'envar: "{_escape(e)}"')
        lines.append(f"rlimit_nofile: {self.rlimit_nofile}")
        lines.append(f"rlimit_as_type: {self.rlimit_as_type}")
        lines.append(
            f'uidmap {{ inside_id: "{self.uid_inside}" outside_id: "{self.uid_outside}" count: 1 }}'
        )
        lines.append(
            f'gidmap {{ inside_id: "{self.gid_inside}" outside_id: "{self.gid_outside}" count: 1 }}'
        )
        for m in self.mounts:
            lines.append("mount {")
            if m.src is not None:
                lines.append(f'  src: "{_escape(m.src)}"')
            lines.append(f'  dst: "{_escape(m.dst)}"')
            if m.fstype is not None:
                lines.append(f'  fstype: "{_escape(m.fstype)}"')
            lines.append(f"  is_bind: {b(m.is_bind)}")
            lines.append(f"  rw: {b(m.rw)}")
            lines.append(f"  mandatory: {b(m.mandatory)}")
            lines.append("}")
        return "\n".join(lines) + "\n"

    @classmethod
    def from_spec(cls, spec: WorkspaceSpec) -> "NsjailConfig":
        check_no_secret_service_mounts(host_mount_sources(spec))
        hostname = f"warren-{spec.workspace_id[:8]}"

        def _abs_dst(container: str) -> str:
            # Audit 2026-10-16 P2 #51: template-declared mount points (e.g.
            # `effective_folders()`'s "code/acme-api") are relative --
            # nsjail's `mount.dst` must be an absolute path inside the jail
            # (unlike podman/docker mount targets, which the daemon resolves
            # against the container's own root). Anchor any relative one
            # under root_path -- the same absolute path it already lives at
            # on the host, since root_path itself is bind-mounted below.
            if container.startswith("/"):
                return container
            return f"{spec.root_path.rstrip('/')}/{container}"

        worktree_mounts = [(host, _abs_dst(c)) for host, c in spec.worktree_paths]
        reference_mounts = [(host, _abs_dst(c)) for host, c in spec.reference_paths]

        cwd = worktree_mounts[0][1] if worktree_mounts else (spec.root_path or "/workspace")

        mounts: list[MountEntry] = []
        # Audit 2026-10-16 P2 #51: root_path itself was never bind-mounted at
        # all -- only worktree/reference subdirectories were -- so anything
        # living directly under the workspace root (not inside a declared
        # worktree/reference folder), and a workspace with no declared
        # folders at all, was invisible inside the jail.
        if spec.root_path:
            mounts.append(
                MountEntry(src=spec.root_path, dst=spec.root_path, rw=True, mandatory=True)
            )
        for host, container in worktree_mounts:
            mounts.append(MountEntry(src=host, dst=container, rw=True, mandatory=True))
        for host, container in reference_mounts:
            mounts.append(MountEntry(src=host, dst=container, rw=False, mandatory=True))
        # Audit 2026-10-16 P2 #51: spec.bind_mounts (template-declared explicit
        # mounts, e.g. [mounts] entries in config.toml) were never passed
        # through to nsjail at all -- podman/docker both honor them.
        for host, container, mode in spec.bind_mounts:
            mounts.append(
                MountEntry(src=host, dst=_abs_dst(container), rw=(mode == "rw"), mandatory=True)
            )
        # System read-only mounts.
        mounts.append(MountEntry(src="/bin", dst="/bin", rw=False, mandatory=True))
        mounts.append(MountEntry(src="/usr", dst="/usr", rw=False, mandatory=True))
        mounts.append(MountEntry(src="/lib", dst="/lib", rw=False, mandatory=False))
        mounts.append(MountEntry(src="/lib64", dst="/lib64", rw=False, mandatory=False))
        mounts.append(
            MountEntry(src="/etc/resolv.conf", dst="/etc/resolv.conf", rw=False, mandatory=True)
        )
        mounts.append(MountEntry(src="/etc/ssl", dst="/etc/ssl", rw=False, mandatory=True))
        # tmpfs for /tmp.
        mounts.append(
            MountEntry(dst="/tmp", src=None, is_bind=False, rw=True, mandatory=False, fstype="tmpfs")
        )
        # AG6: union of the template's harness grants; readonly re-mounted ro last.
        grants = grants_for_spec(spec, Path.home())
        for path in grants.read:
            mounts.append(MountEntry(src=path, dst=path, rw=False, mandatory=False))
        for path in grants.write:
            mounts.append(MountEntry(src=path, dst=path, rw=True, mandatory=False))
        for path in grants.readonly:
            mounts.append(MountEntry(src=path, dst=path, rw=False, mandatory=False))
        # SSH: specific key files ro, agent socket rw (needed for socket protocol).
        for key_path in spec.ssh_key_paths:
            mounts.append(MountEntry(src=key_path, dst=key_path, rw=False, mandatory=True))
        if spec.ssh_agent_sock:
            mounts.append(MountEntry(src=spec.ssh_agent_sock, dst=spec.ssh_agent_sock, rw=True, mandatory=False))
        # S6 follow-up (2026-10-17): spec.env (secrets) used to go straight
        # into `envar: "KEY=VALUE"` lines in nsjail.cfg -- a plaintext copy
        # that then sat on disk for the workspace's entire lifetime (worse
        # than bubblewrap's pre-fix argv exposure: this file persists from
        # provision to destroy, not just for one exec). Secrets now travel
        # the same way bubblewrap already does them: a short-lived 0600 file
        # written fresh by NsjailRuntime.exec() immediately before each
        # invocation and deleted right after, bind-mounted here at a fixed
        # path and sourced by a shell wrapper before the real command runs
        # (see sandbox_env.ENV_SOURCE_SCRIPT). This mount entry only
        # declares *where*; NsjailRuntime.exec() is what actually creates and
        # removes the file each time.
        mounts.append(
            MountEntry(
                src=str(nsjail_secret_env_path(spec.workspace_id)),
                dst=ENV_MOUNT_DEST,
                rw=False,
                mandatory=True,
            )
        )

        return cls(
            hostname=hostname,
            cwd=cwd,
            mounts=mounts,
            # Audit 2026-10-16 P2 #51: real uid/gid instead of a hardcoded
            # 1000 -- on a host where the operator isn't uid/gid 1000,
            # bind-mounted paths they own become wrong-owner (inaccessible)
            # inside the jail.
            uid_outside=os.getuid(),
            gid_outside=os.getgid(),
            seccomp_string=DEFAULT_SECCOMP_POLICY,
        )


def _bool(value: bool) -> str:
    return "true" if value else "false"
