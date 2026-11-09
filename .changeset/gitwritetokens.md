---
warren-common: minor
warren-server: minor
---

Opt-in `git_write: true` templates: the control plane mints a GitHub App installation token per owner for only the template's writable github.com worktree repos (contents + pull_requests write), delivers it with the launch-time secrets, refreshes it before expiry (ECS: KMS envelope over ECS Exec; podman: put_archive), and revokes it on stop/destroy. The workspace's git uses it through git-credential-warren for https://github.com only.
