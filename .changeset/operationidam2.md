---
warren-server: minor
warren-common: minor
warren: patch
---

POST /workspaces and the MCP `new_workspace` tool take an optional client `operationId` (1-64 of `[A-Za-z0-9._:-]`, scoped to the caller): a retry returns the original workspace with its `operation` receipt (`accepted` before provisioning, then `started` or `failed`) instead of launching again, a reused id with a different body is a 409, and `GET /operations/{id}` reads the receipt. Operations persist in the registry database, and on ECS the RunTask clientToken is derived from the operationId. `warren new --server` sends one and reuses it when retrying a dropped connection (AM2)
