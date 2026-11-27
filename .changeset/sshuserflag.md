---
warren: minor
---

`warren ssh-config` takes `--user` for ECS workspaces too, and a remote can set `ssh_user` in its config, so images whose login user is not `warren` work. The value must match the same strict name pattern as every other value written into the generated config; the default stays `warren`.
