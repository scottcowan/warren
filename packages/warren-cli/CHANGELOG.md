# Changelog

## 1.0.0 — 2026-10-03

BREAKING: `warren workspaces <cmd>` no longer works — commands moved to the top level.

- Collapse the 'workspaces' subcommand group — new/destroy/connect/list/status/exec/tunnel are now flat at the top level (warren status, warren tunnel, etc.) instead of behind 'warren workspaces'. secrets/server/project/remote remain namespaced. status and tunnel now prompt interactively for which server to use when --server is omitted, instead of hard-failing.

## 0.1.1 — 2026-10-03

- Fix connect/healthz command collision (healthz was dead code, shadowed by the connect shortcut); fix workspaces list printing spurious config-not-found errors for local-only use; fix docker exec not forwarding stdin

