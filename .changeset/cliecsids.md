---
warren: patch
---

ECS tunnel/exec: the cluster, task ARN and runtime id the server supplies are checked against strict patterns (and the task must belong to the cluster) before they reach an aws argv or an SSM target
