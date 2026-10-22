---
warren-sidecar: minor
warren-server: minor
---

Event streams cursor by seq so they no longer stall after 1,000 events; GET /events and GET /workspaces/{id}/events accept ?since=<seq> and emit an events_evicted marker when that seq has rolled off the ring
