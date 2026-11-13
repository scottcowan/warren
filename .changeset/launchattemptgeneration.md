---
warren-server: patch
---

The DynamoDB launch-attempt store no longer drops an empty `generation` (or other empty identity field) when reading an attempt back, which raised a `KeyError` when retrying a first provision. It now returns the same shape as the SQLite store.
