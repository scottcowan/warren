# Web UI: server-side security design and API inventory

Status: design only, no behaviour change. Written against `main` at `8d3ffe1`.
The proxy half (per-session secret, HttpOnly SameSite=Strict cookie, Host/Origin checks,
no CORS, upstream auth-provider hook) is specified and built separately in branch
`feat-proxy-hardening` (no public PR at the time of writing; link it here when opened).
This document covers what `warren-server` must do so a browser can safely sit behind it.

Method: everything below was derived by reading `packages/warren-server/src/warren/`
(routes, `auth/`, `app.py`, `control_mcp.py`, `http_limits.py`, `ratelimit.py`). Nothing was
run: no server was started and no request was sent. Items I did not read to the bottom are
marked "not verified".

## 1. Authentication and identity

| Layer | Where | Behaviour |
|---|---|---|
| Global gate | `auth/middleware.py` (raw ASGI) | Every http and websocket path needs `Authorization: Bearer`. Only `/_status` and `/healthz` are exempt (`EXEMPT_PATHS`). Unknown scope types fail closed. |
| User bearer token | `auth/tokens.py`, `auth/store.py` | Opaque 256-bit token, stored as peppered hash. Resolves to a `User` (`user_id`, `is_admin`, `disabled_at`). No scope or purpose field: every user token is full API. Expires (`token_ttl_days`), revocable, capped per user (`max_tokens_per_user`). |
| Workspace token | `auth/workspace_tokens.py` | `wrnw_` prefix, one workspace, TTL at most 3600 s, optional Ed25519 proof header. Allowed only for `DELETE`, `GET status/events/git-credential/refs`, `POST exec/git/pull` on its own workspace, `/mcp`, and (reservation tokens) one `POST /workspaces`. Enforced in middleware, so new routes default to denied. |
| Bootstrap token | `auth/bootstrap.py` | `WARREN_BOOTSTRAP_TOKEN` creates the first admin once at startup (user `bootstrap-admin`). Not a runtime credential. |
| Admin | `auth/deps.py` `require_admin` | `User.is_admin`. Gates `/admin/*` and `/healthz/detail` only. |
| AWS identity | `auth/aws_identity.py`, `auth/identity.py` | ECS only: `X-AWS-STS-Signed-Request` verified against `aws_trusted_assumed_role_patterns`. Used only by `resolve_owner_id` (secrets, secret resolution at provision time). |

Identity to `owner_id`:

| Domain | Owner key | Source |
|---|---|---|
| Workspaces, runs, projects (user scope), notifications, tokens | `user.user_id` | bearer token, `routes/workspaces.py:526,950`, `routes/notifications.py` |
| Secrets (podman/docker) | `user.user_id` | `auth/identity.py` `_warren_user_resolver` |
| Secrets (ecs) | verified IAM ARN | `auth/identity.py` `_aws_identity_resolver`, needs the signed header |

So on ECS the workspace owner and the secret owner are different identities (`workspaces.py:325-332`).

## 2. Route inventory

Legend. Who: **U** any valid user token (owner-scoped data), **A** admin only, **WS** workspace-scoped
token also accepted (own workspace only), **none** unauthenticated. Browser-safe: **Y** fine for a read UI,
**act** fine for an action UI behind a scoped token, **N** keep out of the UI scope. CSRF is only relevant if a
route is ever reachable with ambient credentials (cookie); with the bearer-only server today, exposure is
"none (bearer)". The column shows the exposure if cookie auth were used directly against the server.
Untrusted content: **T** transcripts or agent output, **P** template or project text, **N** notification text,
**E** error text echoing input, **-** none.

| Method and path | Who | Reads or changes | Browser | CSRF if cookie | Untrusted content |
|---|---|---|---|---|---|
| GET `/_status` | none | static `{"status":"ok"}` | Y | none | - |
| GET `/healthz` | none | static liveness | Y | none | - |
| GET `/healthz/detail` | A | runtime reachability, workspace and secret counts, socket details | Y (admin) | none | E (backend error strings, not verified) |
| GET `/peers` | U | returns `[]` (stub) | Y | none | - |
| GET `/docs`, `/redoc`, `/openapi.json` | U (behind gate) | FastAPI defaults left on (`app.py` `FastAPI(lifespan=lifespan)`); Swagger loads JS from a CDN | N | none | - |
| GET/POST/DELETE `/mcp` | U, WS | control-plane MCP tools (provision, exec, destroy), owner and scope checked per call (`control_mcp.py:69-93`) | N | high | T, E |
| POST `/workspaces` | U, WS (reservation only) | provisions, spends money, 202 + operation id; rate limited per user | act | high | P, E |
| GET `/operations/{id}` | U | receipt keyed by (principal, id) | Y | none | E |
| GET `/workspaces` | U | all rows from `store.list_all()` filtered in Python (`workspaces.py:950`); includes spec fields | Y | none | P |
| GET `/workspaces/{id}/status` | U, WS | status string | Y | none | - |
| POST `/workspaces/{id}/connect` | U | mints a per-connection SSH key, audited | N | high | - |
| POST `/workspaces/{id}/ensure_running` | U | starts a stopped workspace | act | high | E |
| POST `/workspaces/{id}/git/pull` | U, WS | pulls into server-side worktree | act | high | E (git stderr, `workspaces.py:1225`) |
| GET `/workspaces/{id}/refs` | U, WS | branch and tag names | Y | none | T (ref names are attacker-chosen) |
| POST `/workspaces/{id}/branch` | U | forks a workspace session (202) | act | high | E |
| GET `/workspaces/{id}/events` | U, WS | long-lived NDJSON stream (not SSE) of agent events; `get_or_create` side effect on the buffer | Y (with fetch streaming) | none | T |
| POST `/workspaces/{id}/exec` | U, WS | runs an arbitrary argv in the workspace, streams NDJSON | N | critical | T |
| DELETE `/workspaces/{id}` | U, WS | destroys; unknown id returns 204, foreign id 403 | act | high | - |
| POST `/workspaces/{id}/tokens` | U (WS refused) | mints workspace token | N | high | - |
| POST `/workspace-tokens` | U (WS refused) | pre-mints a reservation token | N | high | - |
| GET `/workspaces/{id}/git-credential` | U, WS | **issues a live GitHub installation token** on a GET, audited, `no-store` | N | high (state-changing GET) | - |
| GET `/runs`, `/runs/{id}`, `/runs/{id}/result` | U; A may read other owners (`?all=true`, `runs.py:64-80`); WS refused | run summaries and agent result | Y | none | T |
| POST `/runs` | U (WS refused) | starts a headless run | act | high | P |
| GET `/projects`, `/projects/{name}` | U | server-wide and own user-scoped YAML, raw text | Y | none | P |
| PUT/DELETE `/projects/{name}` | U (own scope), A (`server_wide=true`) | writes template YAML | act | high | P |
| PUT/GET/DELETE `/secrets`, POST `/secrets/{name}/rotate` | U (ECS: also needs signed header) | secret names list (values never returned), writes and deletes | N for write; list Y | high | - |
| PUT/GET/DELETE `/notifications/webhook` | U | per-user webhook URL (stored as a secret), view shows format and events only | act | high | N (URL and event names) |
| POST/GET `/tokens`, DELETE `/tokens/{id}` | U (WS refused by allow-list) | self-service token mint, list metadata, revoke | N for mint | high | - |
| POST/GET `/admin/users`, POST `/admin/users/{id}/tokens`, GET `/admin/users/{id}/tokens`, POST `/admin/users/{id}/disable`, DELETE `/admin/tokens/{id}` | A | create users, mint a token for any user, list tokens, disable, revoke | N | critical | E |

Surprising, read from code:

- Token scope does not exist for user tokens; "UI token" cannot be expressed today (F1).
- `/runs` has an admin read bypass; `/workspaces` and its sub-routes deliberately have none (`workspaces.py:940-947`).
- `GET git-credential` mints a credential (state-changing GET).
- `/workspaces` and `/secrets` etc. have no pagination; only `/runs` caps (`limit` le 500).
- Events are NDJSON over a plain streaming GET: `EventSource` cannot be used (no custom headers).
- No websocket routes exist. The middleware does handle websocket scopes (close codes 4401/4403/4429).
- Rate limiting covers only workspace create (per user) and failed auth (per client IP).

## 3. Findings, ranked

| # | Sev for a browser UI | Finding | Evidence | Failure scenario |
|---|---|---|---|---|
| F1 | High | User tokens are unscoped. Any token is full API including exec, secrets, token minting, git credentials. | `auth/models.py` `Token` has no scope field; `routes/tokens.py:38-80` | A UI session token stolen by an XSS bug in transcript rendering, or by a malicious local process reading proxy state, runs `POST /workspaces/{id}/exec` or mints a 30-day token. |
| F2 | High | Any token can mint further full-power tokens; mint and revoke are only `log.info`, no `audit_event`. | `routes/tokens.py:38-80` (cap only), grep: zero `audit_event` in `routes/tokens.py`, `routes/admin.py` | A short-lived UI token calls `POST /tokens` once and the attacker keeps a long-lived token after the UI session ends; the audit stream (T15) has no record of it. |
| F3 | High | Admin routes allow impersonation: an admin mints a token for any `user_id`, owner checks then pass as that user. No audit event. | `routes/admin.py:110-153` | An admin browser session compromised via the UI yields a token for every owner, so every "owner only" control (D-11) is bypassed silently. |
| F4 | Medium | `/runs` lets an admin read any owner's runs; elsewhere admin has no bypass. Inconsistent, and results contain agent output. | `routes/runs.py:64-80`, `140-153` vs `workspaces.py:940-947` | An admin dashboard silently shows other users' run transcripts; the single `run.read` audit event is the only trace. |
| F5 | Medium | No rate limit on authenticated routes (only workspace create). SPA polling plus expensive handlers such as `/workspaces` (full table scan) and git-credential minting are unthrottled. | `grep` for limiter use: `routes/workspaces.py:58`, `auth/middleware.py:60` only | A looping or buggy tab hammers `GET /workspaces` and `git-credential`, loading the state store and the GitHub App API. |
| F6 | Medium | Unbounded lists and streams: `/workspaces` (`list_all` then Python filter), `/secrets`, `/projects`, `/tokens`; `/events` has no per-user connection cap. | `routes/workspaces.py:950`, `routes/workspaces.py:1300-1337` | Many tabs each hold an NDJSON stream; table growth makes every list slower for everyone. |
| F7 | Medium | ECS secret ownership needs `X-AWS-STS-Signed-Request` and is keyed by IAM ARN, not `user_id`. A bearer-only browser gets 401 on `/secrets` and cannot see the secrets its own workspaces use. | `auth/identity.py` `_aws_identity_resolver`; `workspaces.py:325-332` | UI shows an empty or failing secrets page on ECS, or a naive fix (skip the check for web tokens) lets bearer holders read another identity's secret namespace. |
| F8 | Medium | State-changing GET: `git-credential` returns a live GitHub token. Any full-scope bearer reaches it. | `routes/git_credentials.py:32-80` | If the SPA ever uses a cookie-authenticated path or a prefetcher follows the URL, tokens are minted and logged in browser history or caches (`no-store` helps only the response). |
| F9 | Low | 404 vs 403 reveals that a foreign workspace id exists; `DELETE` returns 204 for unknown and 403 for foreign. | `workspaces.py:955-962`, `1425-1437` | An attacker with a valid token probes ids. UUID4 makes this impractical; documented in code. |
| F10 | Low | Defence in depth missing: `status`, `events`, `connect`, `ensure_running`, `git/pull` do not call `require_workspace_access`; they rely only on the middleware allow-list. | `workspaces.py:953,1300` vs calls at `1199,1352,1431` | A future edit that adds a path to `_SCOPED_ROUTES` exposes a handler with no second check. |
| F11 | Low | Error bodies echo exception text (`str(exc)`) for template, git and token-key errors. | `workspaces.py:362,439,709,1225`; `routes/workspace_tokens.py` | Git stderr containing remote URLs or repo-chosen strings is rendered in the UI; must be text-only. |
| F12 | Low | FastAPI `/docs`, `/redoc`, `/openapi.json` are on (behind auth). Swagger UI pulls scripts from a CDN, which a strict CSP would block and which should not be served alongside the SPA. | `app.py` `FastAPI(lifespan=lifespan)` | Operator opens `/docs` in the same origin as the SPA; third-party script runs with the cookie. |
| F13 | Low | Failed-auth limiter is keyed by client IP; behind a loopback proxy or SSM forward every client is `127.0.0.1`, so one stale browser tab spends the shared 20/min budget and CLI failures turn into 429. Valid tokens are not throttled (checked before the limiter). | `auth/middleware.py:60-62,198-216` | Misleading 429s, no lockout of valid users. Key on token prefix or session id as well. |
| F14 | Low | Audit coverage is partial: provision, connect, exec, destroy, secrets, notifications, workspace tokens, git credentials, one run read. Missing: ensure_running, git pull, branch, events, projects write/delete, `/tokens`, all `/admin`. | `grep audit_event` per file | Cannot reconstruct who edited a template or created users. |
| F15 | Info | No CORS, no Host check, no security headers on the server. Safe today because every route except `/_status` and `/healthz` needs a bearer header. | `app.py` (no CORS or TrustedHost middleware) | Becomes DNS-rebinding relevant the moment the server accepts cookies. This is why the design below keeps the server bearer-only. |

Verified by reading: all of the above. Run: nothing.

## 4. Browser session design

### 4.1 Creation (recommended)

1. User runs `warren ui` (or `warren proxy` with the UI flag). The CLI already holds the user's identity (bearer, plus the signed AWS header on ECS).
2. CLI calls a new `POST /web-sessions` with its normal credential. Server mints a **web-session token** (`wrnu_` prefix), bound to `user_id`, `scope=ui-read` or `ui-act`, TTL 15 minutes sliding to a hard cap of 8 hours, and returns it once.
3. The CLI hands that token to the local proxy over its private channel (never in a URL). The proxy injects `Authorization: Bearer wrnu_...` upstream; the browser only ever holds the proxy's HttpOnly SameSite=Strict cookie.
4. Renewal: `POST /web-sessions/refresh` with the current token returns a new token and revokes the old one (rotation). Hard cap enforced server-side from the original `created_at`.

Alternatives considered:

| Option | Verdict |
|---|---|
| Browser holds the user's long-lived token | Rejected: full scope, long life, stored in page JS or storage. |
| Server login page with password or OIDC and its own cookie | Rejected for now: adds a credential store and cookie CSRF surface; there is no identity provider on the loopback-only server. Revisit if the server ever has a public listener. |
| Proxy injects the user's existing token | Rejected: cannot be scoped or revoked independently of the CLI token (F1). |
| Per-request SigV4 or STS header from the proxy | Rejected: replay window and signing in the proxy widens its trust. Needed only for ECS secrets (F7), see 4.8. |

### 4.2 Scopes

| Scope | Allows | Denies |
|---|---|---|
| `ui-read` | GET `/workspaces`, status, refs, events, `/runs*`, `/projects*`, `/operations/*`, `/secrets` (names), `/notifications/webhook`, `/ui/*`, `/version` | everything that writes, `/mcp`, `/admin/*`, `git-credential`, `connect`, `/tokens*`, `/web-sessions` except refresh and delete-self |
| `ui-act` | `ui-read` plus ensure_running, git/pull, branch, DELETE workspace, POST `/workspaces`, POST `/runs`, project writes (user scope) | `exec`, secrets writes, token minting, `git-credential`, `connect`, server-wide project writes, admin |
| (never for web) | exec, git-credential, connect, token mint, admin | |

Implement as an allow-list in `AuthMiddleware`, the same mechanism workspace tokens use (`scoped_request_allowed`), so a new route is denied to web tokens until listed.

### 4.3 Lifetime, revocation, binding, audit

| Aspect | Design |
|---|---|
| Binding | `user_id` fixed at mint; `owner_id` derived exactly as today, so all D-11 checks apply unchanged. Disabled user kills all web tokens (same `disabled_at` join). |
| Revocation | `DELETE /web-sessions/{id}`, `warren ui --stop`, and revoke-on-disable. Also revoked when the minting CLI token is revoked (`created_by_token_id` lineage, which already exists). |
| Count | Separate small cap (for example 5 live web sessions per user) so UI tokens do not consume `max_tokens_per_user`. |
| Audit | New `audit_event`s: `web_session.create`, `.refresh`, `.revoke`, `.denied_scope` (carrying route, never token). Every UI-initiated mutation also carries `via="web"` and the session id in the existing events. |
| Storage | Hash only, same pepper scheme as `auth/tokens.py`. |

### 4.4 CSRF stance

Recommendation: **bearer-only on the server, with the proxy injecting the Bearer.** The server never accepts a cookie, so
there is no ambient credential at the server and no server-side CSRF surface to defend. CSRF is then a proxy concern:
the proxy's SameSite=Strict cookie plus its Host and Origin checks (branch `feat-proxy-hardening`) must reject cross-site
state-changing requests, and the server adds defence in depth by requiring `X-Warren-Client: ui` (custom header, forces a
preflight that no CORS policy will approve) on every non-GET web-token request.
Why not cookie auth directly against the server: it needs its own CSRF tokens, Origin checks, DNS-rebinding defences
(F15) and cookie hygiene, duplicating what the proxy does, for no gain on a loopback-only service.

### 4.5 CORS, headers, CSP, cookies

| Item | Setting |
|---|---|
| CORS | None. No `Access-Control-*` headers on any route. Same-origin only (SPA served by the same origin the proxy fronts). |
| CSP (on `/ui/*`) | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'`. No inline script, no `eval`, no `unsafe-inline`. Build step must emit hashed external bundles. |
| Other headers | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy` empty, `Cache-Control: no-store` on API responses, `Cache-Control: public, max-age=31536000, immutable` only on hashed assets, `no-cache` on `index.html`. |
| Cookie (proxy) | `HttpOnly; SameSite=Strict; Path=/; Secure` when the proxy uses TLS; use `__Host-` prefix when possible. Not set by the server. |

### 4.6 Streaming authentication

`/events` is NDJSON over `fetch`, so the proxy-injected Bearer applies as for any request. Do not use `EventSource` or
add `?token=` query auth (URLs leak into logs and history). No WebSockets exist; if one is added, authenticate on the
handshake via the same middleware, require a matching `Origin` check at the proxy, and never accept tokens in the query
string. Add a per-user cap on concurrent streams (for example 8) and a server idle timeout.

### 4.7 Rate limiting, lockout, logging

| Item | Design |
|---|---|
| Rate limit | Per-token sliding window for web tokens on all routes (generous read limit, tight write limit), using the existing `SlidingWindowRateLimiter`. Separate limit on `git-credential` and `POST /web-sessions`. |
| Lockout | Failed-auth limiter keyed on client IP plus token prefix, so a stale tab cannot starve others (F13). Repeated scope denials revoke the session. |
| Logging | Never log `Authorization`, cookies, query strings with tokens, request bodies of `/secrets`, or response bodies. Log token id and session id only. Keep the existing `auth_denied` static-reason pattern. Access logs must drop the `Authorization` header and redact the `wrn*_` token patterns. |

### 4.8 Untrusted output rendering

| Source | Rule |
|---|---|
| Transcripts, events, run results, git stderr, ref names, template text, notification text, error `detail` | Render as text nodes only (`textContent`), never HTML or Markdown-to-HTML. No `dangerouslySetInnerHTML`, no `innerHTML`, no `srcdoc`. |
| ANSI and control characters | Parse SGR colour codes into a fixed allow-list of CSS classes; strip all other escape sequences (OSC 8 hyperlinks, cursor movement, title set, bell) and C0/C1 controls except newline and tab. Cap line length and total rendered bytes. |
| Links | Never auto-link. If linking is wanted later: allow only `https:` URLs, `rel="noopener noreferrer"`, `target="_blank"`, an interstitial showing the real host, no `javascript:`, `data:`, `file:`. |
| Images and embeds | None from untrusted content. `img-src 'self' data:` only. |
| JSON | Parse with `JSON.parse`; ignore unknown keys; treat ids as opaque strings; do not use them as DOM ids or in selectors. |
| ECS secrets (F7) | Hide the secrets page on ECS until a design exists (CLI-only), do not weaken `resolve_owner_id`. |

## 5. Server changes required

Size: S under a day, M a few days, L about a week or more.

| # | Change | Size | Needed for |
|---|---|---|---|
| 1 | Token scope model: `scope` column on tokens, `wrnu_` prefix, middleware allow-list (`ui-read`, `ui-act`), tests that every route is classified (see fixture below) | M | read-only UI |
| 2 | `POST /web-sessions`, refresh, list, delete; caps, hard lifetime, revoke-on-disable and on parent revoke | M | read-only UI |
| 3 | Audit events for web sessions, `/tokens`, `/admin/*`, projects, ensure_running, git pull, branch (F2, F3, F14) | S | read-only UI (token events), actions (rest) |
| 4 | Deny web scopes on exec, connect, git-credential, token mint, `/mcp`, admin; stop `/tokens` self-mint accepting web tokens | S (part of 1) | read-only UI |
| 5 | Pagination (`limit`, `cursor`) on `/workspaces`, `/secrets`, `/projects`, `/tokens`, with a SQL-side owner filter instead of `list_all` | M | read-only UI |
| 6 | Per-token rate limit middleware and a cap on concurrent `/events` streams | M | read-only UI |
| 7 | `GET /version` (unauthenticated is fine, or `ui-read`): server version, API version integer, `ui_enabled`, capability flags (scopes, ecs-secrets-supported). SPA checks it on load and refuses to run on an API major mismatch | S | read-only UI |
| 8 | `/ui` static mount behind `WARREN_UI_ENABLED` (default off) and `WARREN_UI_DIR`; see hardening list below | M | read-only UI |
| 9 | Security headers middleware (4.5), applied to `/ui/*` and API; disable `/docs`, `/redoc`, `/openapi.json` unless `WARREN_API_DOCS=1` | S | read-only UI |
| 10 | Make `/runs` admin bypass explicit and audited per read, or remove it for consistency with D-11 (F4); decision needed | S | read-only UI (admin views) |
| 11 | `require_workspace_access` in every workspace handler (F10); uniform 404 for foreign ids on status, events, connect, git-pull, delete (F9) | S | actions |
| 12 | `X-Warren-Client: ui` requirement on web-token mutations (4.4) | S | actions |
| 13 | Sanitised error envelope: stable `error` codes, no raw `str(exc)` for git or template errors on web scopes (F11) | M | actions |
| 14 | Failed-auth limiter key change (F13) | S | actions |
| 15 | ECS secrets story for the UI (F7): CLI-only for now, or a signed-session design | L | later |

Static serving hardening (item 8):

| Control | Detail |
|---|---|
| Path traversal | Resolve with `Path.resolve()` and require `is_relative_to(ui_dir.resolve())`; reject `..`, absolute paths, NUL, backslashes; refuse symlinks that leave the root (`follow_symlinks=False` or explicit check). Do not use a catch-all `StaticFiles` mount without these checks. |
| Allowed files | Only files present in a build manifest generated at build time; everything else is 404. SPA fallback serves `index.html` only for paths without a file extension and only for GET. |
| Content types | Fixed extension map (`.js` `text/javascript`, `.css`, `.html`, `.svg` only if sanitised, `.woff2`, `.png`, `.map` disabled in production); `nosniff` always; never guess from content. |
| Caching | Hashed assets immutable; `index.html` `no-cache`; API `no-store`. |
| Methods | GET and HEAD only; no directory listing; no Range on `index.html`. |
| Auth | Static assets unauthenticated is acceptable (public code, no data) but must be same-origin behind the proxy; the exempt-path list is not extended for them unless explicitly decided (open question 2). |
| Default | Off. When off, `/ui` returns 404 and no files are read. |

Route-classification fixture: `packages/warren-server/tests/fixtures/route_inventory.tsv` is NOT added in this PR
(docs only). Item 1 should add a test that enumerates `app.routes` and fails if a route has no scope classification.

## 6. Threat model additions

Drafted here and added to `docs/threat-model.md` as T21 to T24 and residual risks 15 to 17.

| # | Threat | Control | Where |
|---|---|---|---|
| T21 | A browser session token is stolen (XSS, local process, proxy state) and used with full API power | Web-session tokens are a distinct scope with an allow-list that excludes exec, connect, git credentials, token minting and admin; short TTL with hard cap; revoke on disable. Tokens never reach page JS (proxy holds them) | design, not yet built |
| T22 | Cross-site request forges a state-changing call through the proxy | Server stays bearer-only (no cookie auth); proxy cookie is HttpOnly SameSite=Strict with Host/Origin checks; `X-Warren-Client` header on web mutations; no CORS | design, proxy branch `feat-proxy-hardening` |
| T23 | Agent-controlled text (transcripts, run results, git errors, ref names, template text) executes script or spoofs UI in the SPA | Text-only rendering, ANSI allow-list, no auto-linking, strict CSP (no inline script, no eval, `frame-ancestors 'none'`, Trusted Types) | design, not yet built |
| T24 | Admin session turns into impersonation of every owner | Admin routes denied to web scope; audit events for admin mint, disable and revoke; decision on `/runs` admin bypass | design, not yet built |

Residual risks to append:

15. **Admin can mint a token for any user.** `POST /admin/users/{id}/tokens` is by design an impersonation primitive and is not yet audited as an event. Treat the admin token as equivalent to every owner's.
16. **Unscoped legacy user tokens remain full API.** Until the web-session scope ships, any token the CLI holds can exec and mint further tokens; a UI must not be exposed before it does.
17. **Rendering agent output in a browser is a new injection surface.** Even with text-only rendering and strict CSP, a bug in the ANSI or link handling is reachable by anything the agent can print.

## 7. Open decisions for the owner

| # | Question | Default if no answer |
|---|---|---|
| 1 | `/runs` admin bypass: keep (audited) or remove? | Remove for consistency with D-11 |
| 2 | Serve `/ui` assets without auth (simplest, proxy cookie still gates), or behind the bearer? | Behind the proxy only; unauthenticated at the server |
| 3 | ECS secrets in the UI: CLI-only for v1? | Yes |
| 4 | Initial UI scope: read-only first, actions later? | Yes, per the checklist ordering |
| 5 | Web-session limits: 15 min sliding, 8 h hard, 5 per user? | As stated |
