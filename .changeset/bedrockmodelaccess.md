---
warren-common: minor
warren: minor
warren-server: minor
---

Template `model_access: subscription | bedrock` (also inferred from CLAUDE_CODE_USE_BEDROCK / ANTHROPIC_BEDROCK_BASE_URL). Bedrock-mode workspaces never get the operator's Claude OAuth token: no Keychain read, no .credentials.json, CLAUDE_CODE_OAUTH_TOKEN secrets rejected. Models are reached through the workspace's own AWS identity (local aws export endpoint, ECS task role), and local connect fails clearly without AWS credentials or a region
