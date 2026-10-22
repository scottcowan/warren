---
warren-server: patch
---

Document that Fargate allows no in-task sandbox (everything in an ECS workspace task is agent-controlled) and guard the workspace task role against new permissions in all three IaC paths (AD1)
