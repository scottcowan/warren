---
warren-server: patch
---

EBS and bare-seed sweeps, purge, restore and seed cleanup re-describe a volume or snapshot and re-check its ownership tags immediately before every delete or restore, so a stale listing or a recorded id pointing at a retagged or foreign resource is never deleted or restored; a run owned by another user now returns the same 404 as a missing run
