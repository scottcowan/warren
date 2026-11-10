---
warren: patch
---

ssh-config: podman/docker key files and HostKeyAlias use an unambiguous `server+workspace` name (distinct pairs like a-b/c and a/b-c no longer share a key or known_hosts entry), the old ambiguous key file is removed on re-issue, and the key is written through a unique temp file
