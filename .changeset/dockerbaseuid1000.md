---
warren-server: minor
---

warren-docker-base runs its workload (tmux, harness init, agent supervisor, app) as `warren` (uid 1000) instead of container root when the bind mounts are owned by uid 1000 (podman keep-id, the default), so files the agent creates in the checkout are the server user's and `git/pull` and cleanup need no `podman unshare`. It stays root under `WARREN_PODMAN_USERNS=host` and over root- or other-uid-owned docker mounts. The podman runtime runs `exec` sessions as uid 1000 for images that carry the `dev.warren.workload-uid` label (git token ownership steps still run as root), and `warren-docker-ssh-base` no longer fails to create `warren` when the base already has it.
