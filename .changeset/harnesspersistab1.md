---
warren-common: minor
warren-server: minor
---

Harness conversation history survives task relaunch and image upgrade: podman workspaces mount `<data_dir>/harness/<id>` at /var/lib/warren/harness (removed on destroy); ECS keeps it on the workspace's EFS access point. At every container start the entrypoints keep only each harness's declared `persist` paths and delete credential files inside them; profiles are checked so `persist` never covers credentials, settings or code (AB1)
