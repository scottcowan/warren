---
warren-server: minor
warren-common: patch
---

Add owner-only GET /workspaces/{id}/files, /files/{path}, /diff and /agent-state; file and diff queries run the images' warren-query script as the workspace user over the runtime's exec channel, never via the sidecar
