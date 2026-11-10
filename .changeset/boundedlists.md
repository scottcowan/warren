---
warren-server: minor
warren: patch
---

`GET /workspaces` is now paged: `?limit=` (default 100, max 500) and `?cursor=`, newest first, with the next page's opaque cursor in the `X-Next-Cursor` response header. It is served by a new owner-filtered `list_for_owner` store query on SQLite and DynamoDB instead of loading every workspace. `GET /workspaces/{id}/events` now ends each connection after 1 hour or 10000 lines (resume with `?since=`). The CLI follows the cursor, so `warren` commands still see every workspace
