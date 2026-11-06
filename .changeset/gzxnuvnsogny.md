---
warren-server: minor
warren-common: minor
warren: minor
---

warren proxy reaches podman/docker workspaces: each template-declared port is published on the server host's loopback on an ephemeral host port (never 0.0.0.0, even when WARREN_SSH_PUBLISH_HOST is wider), recorded per port name after every container create/start and returned in GET /workspaces as host_ports; warren proxy forwards to it over ssh -L for ssh remotes and directly for a local http remote, re-resolving when the host port moves. The server warns at startup when rootless podman uses pasta, which lets containers reach host loopback via 169.254.1.2
