---
warren-server: minor
warren: minor
---

warren secrets rotate <name> (local --project or --server); POST /secrets/{name}/rotate replaces the value or, without one, re-encrypts it under the current key (AH6)
