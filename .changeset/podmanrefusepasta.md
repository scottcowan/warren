---
warren-server: minor
---

The server refuses to start on rootless podman when the network helper is pasta (workspaces could reach host loopback via 169.254.1.2, including other workspaces' published ports). Set `default_rootless_network_cmd = "slirp4netns"` in containers.conf, or `WARREN_PODMAN_ALLOW_PASTA=1` to accept the risk. Rootful podman, docker and ECS are unaffected.
