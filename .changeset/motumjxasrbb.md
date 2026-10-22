---
warren-server: minor
---

Tag every ECS workspace task with warren.owner_id (server-derived); IaC scopes human ECS Exec by that tag, denies ssm:StartSession into workspace tasks, and adds a break-glass role as the only cluster-wide exec holder (AI1)
