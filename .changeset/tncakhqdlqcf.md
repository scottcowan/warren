---
warren-server: patch
---

Warn at startup (podman_pasta_apparmor) when podman info shows rootless podman 5.x using pasta with AppArmor enabled, the Ubuntu 26.04 combination where container removal fails; the fix is default_rootless_network_cmd = "slirp4netns"
