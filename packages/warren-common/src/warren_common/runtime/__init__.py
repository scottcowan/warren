"""
Runtime abstraction — warren is agnostic to the container technology.

Local implementations (used directly by warren-cli, no server required):
  NsjailRuntime      — local workspaces (Jetson-class ARM64 edge devices)
  BubblewrapRuntime  — local workspaces (Linux namespaces)
  SeatbeltRuntime    — local workspaces (macOS sandbox-exec)
  DockerRuntime      — daemon-backed, local or remote hosts

Server-hosted implementations (ECSRuntime, PodmanRuntime, ...) live in
warren-server, which depends on this package for the shared Protocol
and dataclasses below.
"""
from warren_common.runtime.base import ContainerRuntime, RuntimeConfig, WorkspaceHandle, WorkspaceSpec

__all__ = ["ContainerRuntime", "RuntimeConfig", "WorkspaceHandle", "WorkspaceSpec"]
