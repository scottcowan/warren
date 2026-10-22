"""
Runtime abstraction — warren is agnostic to the container technology.

Server-hosted implementations (this package):
  PodmanRuntime   — node2 primary (rootless, daemonless)
  ECSRuntime      — AWS Fargate

Local implementations (NsjailRuntime, DockerRuntime, BubblewrapRuntime,
SeatbeltRuntime) live in warren_common.runtime — they're used directly by
warren-cli with no server involved, and warren-server's DockerRuntime
config option imports the shared copy from there too.
"""
from warren_common.runtime.base import ContainerRuntime, RuntimeConfig, WorkspaceHandle, WorkspaceSpec

__all__ = ["ContainerRuntime", "RuntimeConfig", "WorkspaceHandle", "WorkspaceSpec"]
