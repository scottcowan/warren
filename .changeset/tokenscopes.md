---
warren-server: minor
---

User tokens now carry a scope (`full`, `ui-read` or `ui-act`; existing tokens migrate to `full`). `POST /tokens` takes an optional `{"scope": ...}` body and returns the scope. AuthMiddleware confines ui scopes to a named route allow-list (403 otherwise), a child token can never be broader or longer-lived than the token that minted it, and revoking a token (`DELETE /tokens/{id}`, `DELETE /admin/tokens/{id}`) also revokes every token minted from it. SQLite and DynamoDB (new `TOKENCHILD#` lineage index, queried not scanned) behave the same
