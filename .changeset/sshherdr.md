---
warren-server: minor
---

`warren-ecs-ssh-base` and `warren-docker-ssh-base` ship herdr v0.9.5 at `/usr/local/bin/herdr` (root-owned 0755, release asset checked against a pinned per-architecture sha256 at build) so `herdr machine add <ssh-alias>` works against a workspace; its background update checks are off and `herdr update` must not be used in the image. See docs/workspace-ssh.md.
