---
warren-sidecar: minor
warren-common: minor
warren-server: patch
warren-mcp: patch
---

warren-sidecar is now only the in-container agent-state recorder (OSC 7501 -> osc-state.json): its HTTP API, socket and token are gone; WorkspaceHandle drops the unused sidecar_url/sidecar_socket_path fields and runtimes no longer mint WARREN_SIDECAR_TOKEN
