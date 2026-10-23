---
warren-sidecar: patch
warren-server: patch
warren-common: patch
---

Sidecar requires its per-workspace token on every route but /healthz (incl. /diff and /events), which podman/docker provisioning now mints and the server stores encrypted; file reads apply the listing's exclusions and never follow symlinks
