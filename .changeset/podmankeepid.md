---
warren-server: minor
warren-docker-base: patch
---

Rootless podman workspaces run in a `keep-id:uid=1000,gid=1000` user namespace by default (`WARREN_PODMAN_USERNS`, podman >= 4.3; `host` opts out), so the checkout and other bind mounts are owned by `warren` (uid 1000) inside and what `warren` writes is the server user's on the host. The container still starts as the image's USER (root). Destroy removes files container root wrote through `podman unshare` when needed, harness state the server can't read host-side is read through the podman API, and the warren-docker-base entrypoint hands what its harness init writes to the harness dir's owner
