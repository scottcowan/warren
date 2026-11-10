---
warren-server: patch
---

Failed-auth limiter keyed by client IP plus token prefix; per-token request budget on GET /workspaces, git-credential and POST /runs (WARREN_REQUEST_BUDGET_MAX / _WINDOW_SECONDS); /docs, /redoc, /openapi.json off unless WARREN_ENABLE_DOCS=1; nosniff, no-store, no-referrer headers on authenticated responses.
