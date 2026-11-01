---
warren-common: minor
warren: minor
warren-server: minor
---

opencode and codex harness profiles checked against opencode 1.19.5 and codex 0.166.0: `agent.mode` picks a named mode (opencode `acp`/`serve`, codex `exec`/`app-server`/`app-server-stdio`), and self-serving modes run under the supervisor on the agent port (`transport: self`, `WARREN_APP_PORT` set); opencode's data and state follow XDG into the harness dir (persisted, credentials removed); opencode and codex provider config is generated from the Bedrock/gateway env; codex hooks use `[features] hooks` and are trusted by hash so they actually run; doctor checks opencode and codex versions; docs/harnesses.md has the harness matrix
