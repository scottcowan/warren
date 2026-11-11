---
warren-server: minor
---

Workspace tokens: a user can hold at most `WARREN_MAX_WORKSPACE_TOKENS_PER_USER` (default 50) live workspace and reservation tokens, and minting beyond that returns 429 "too many active workspace tokens". Expired and revoked rows are purged (DynamoDB TTL; a SQLite cleanup loop after `WARREN_WORKSPACE_TOKEN_RETENTION_DAYS`, default 7). Key-bound tokens get v2 proofs (`X-Warren-Proof: v2.<ts>.<sig>`) that sign the request body's SHA-256. v1 proofs are accepted, with a deprecation warning in the log, until `WARREN_WORKSPACE_TOKEN_LEGACY_PROOF_UNTIL` (default 2027-03-01; empty rejects them now); update workspace-side signers to v2 before then
