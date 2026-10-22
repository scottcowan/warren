---
warren-common: minor
warren: minor
warren-server: minor
---

Harness profile registry (claude, codex, opencode, cursor-agent, pi, custom) with template validation and allow_vendor_cloud; sandbox grants built from the union of a template's harnesses, with every host harness config dir write-denied; per-workspace harness config dirs (CLAUDE_CONFIG_DIR, CODEX_HOME, ...) seeded from non-secret settings, with the Claude OAuth access token brokered in from the Keychain per launch (AG1, AG3, AG6, AJ1)
