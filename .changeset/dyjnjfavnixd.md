---
warren-server: patch
---

GET/POST /workspaces no longer return the persisted spec (secret names, folders, mounts, template env, ssh/aws/scope) or the host root_path; only app, also as a one-key spec_json (BB15)
