---
warren-server: minor
---

Optional AWS state backends for ECS deployments: `WARREN_STATE_BACKEND=dynamodb` keeps the registry, launch attempts, EBS snapshots/seeds, operations, idle stops, users, tokens and headless runs in one DynamoDB table, and `WARREN_SECRETS_BACKEND=secretsmanager` keeps user secrets (notification webhooks included) in AWS Secrets Manager. SQLite stays the default for both. Includes startup preflight, `warren-server --migrate-state` (dry run unless `--apply`) and opt-in Terraform/CDK.
