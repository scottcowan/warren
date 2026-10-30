---
warren-server: minor
warren-common: minor
---

ECS workspaces can use EBS storage (WARREN_ECS_WORKSPACE_STORAGE=ebs, or a template's ecs_storage): an ECS-managed volume snapshotted on every stop, restored on relaunch and deleted with all its snapshots on destroy, with secrets delivered as per-container KMS envelopes
