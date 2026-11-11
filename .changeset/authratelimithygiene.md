---
warren-server: patch
---

Failed-auth limiter keyed by client IP plus token prefix; per-token request budget on GET /workspaces, git-credential and POST /runs (WARREN_REQUEST_BUDGET_MAX / _WINDOW_SECONDS); /docs, /redoc, /openapi.json off unless WARREN_ENABLE_DOCS=1; nosniff, no-store, no-referrer headers on authenticated responses.

HTTP error bodies for invalid templates, webhooks, public keys, argv, ref and provisioning failures, and AWS identity failures now carry fixed messages instead of raw exception text (shape unchanged: error code plus detail); details are logged server-side.
