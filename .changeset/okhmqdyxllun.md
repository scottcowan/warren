---
warren-server: patch
warren-common: patch
warren-sidecar: patch
---

Stop storing per-workspace sidecar tokens: nothing outside the container calls the sidecar, so each container gets a fresh token held only in its env; previously stored tokens (incl. destroyed and reaped rows) are dropped at startup
