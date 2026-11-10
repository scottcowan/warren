---
warren-server: patch
---

The SQLite to DynamoDB state migration writes each multi-item row (a token is three items) in one transaction, so an interrupted run can no longer leave a half-copied row that a rerun skips
