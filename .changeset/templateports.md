---
warren-common: minor
warren-server: minor
warren: minor
---

Named template ports: a template's optional `ports` mapping (`{t3: 3773, code: {port: 8080, description: ...}}`, names `[a-z0-9-]+`, unique port numbers, merged key by key through nested templates) is persisted with the workspace and returned in `GET /workspaces` as `ports`; `warren proxy add <ws> --from-template` maps every declared port idempotently as `<ws>/<name>`, `warren proxy add <ws> <name>` maps one by name, and `warren proxy list`/`rm` show and accept the names
