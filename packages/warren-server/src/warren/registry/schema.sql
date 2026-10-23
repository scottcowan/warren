CREATE TABLE IF NOT EXISTS workspaces (
    workspace_id     TEXT PRIMARY KEY,
    project          TEXT NOT NULL,
    intent           TEXT NOT NULL,
    image            TEXT NOT NULL,
    root_path        TEXT NOT NULL,
    container_id     TEXT,
    status           TEXT NOT NULL,
    server_instance  TEXT NOT NULL,
    labels_json      TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    ssh_port         INTEGER,
    owner_id         TEXT,
    idle_ttl_seconds REAL,
    spec_json        TEXT,
    sidecar_token_enc BLOB
);

CREATE INDEX IF NOT EXISTS idx_workspaces_status ON workspaces(status);
CREATE INDEX IF NOT EXISTS idx_workspaces_server ON workspaces(server_instance);

-- AI3: the ECS launch identity (task definition + RunTask clientToken) for a
-- workspace's current provision generation, written BEFORE RunTask so a retry
-- after a lost RunTask response reuses it instead of launching a second task.
CREATE TABLE IF NOT EXISTS ecs_launch_attempts (
    workspace_id         TEXT PRIMARY KEY,
    generation           TEXT NOT NULL,
    fingerprint          TEXT NOT NULL,
    task_definition_arn  TEXT NOT NULL,
    client_token         TEXT NOT NULL,
    created_at           TEXT NOT NULL
);

-- AM2: client-supplied launch operations, keyed per principal, so a retried
-- provision returns the original workspace instead of launching a second one.
CREATE TABLE IF NOT EXISTS operations (
    principal     TEXT NOT NULL,
    operation_id  TEXT NOT NULL,
    kind          TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    stage         TEXT NOT NULL,
    workspace_id  TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    PRIMARY KEY (principal, operation_id)
);

-- AH10: workspaces the idle reaper stopped, and when. Cleared by any later status
-- change other than "stopped", so only an untouched idle stop ages into a destroy.
CREATE TABLE IF NOT EXISTS idle_stops (
    workspace_id  TEXT PRIMARY KEY,
    stopped_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    username     TEXT NOT NULL UNIQUE,
    is_admin     INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    -- Issue #11: nullable disabled-since timestamp, matching the revoked_at/expires_at
    -- convention below rather than a plain boolean. A disabled user's tokens must stop
    -- authenticating immediately (checked in AuthStore.get_active_user_by_hashed_token).
    disabled_at  TEXT
);

CREATE TABLE IF NOT EXISTS tokens (
    token_id             TEXT PRIMARY KEY,
    user_id              TEXT NOT NULL REFERENCES users(user_id),
    hashed_token         TEXT NOT NULL UNIQUE,
    created_at           TEXT NOT NULL,
    expires_at           TEXT,
    revoked_at           TEXT,
    -- Issue #11: which token minted this one (NULL for the bootstrap admin's first
    -- token). Provenance only -- cascading revocation of a token's lineage is not
    -- implemented yet, a reasonable follow-up, not blocking this fix.
    created_by_token_id  TEXT
);

CREATE INDEX IF NOT EXISTS idx_tokens_hashed_token ON tokens(hashed_token);
CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);

-- Local (Podman/Docker) secret store (warren.secrets) — Fernet-encrypted at rest,
-- keyed from WARREN_SECRET_KEY; the single source of truth on every runtime,
-- including ECS (ECS additionally mirrors to AWS SSM Parameter Store on write,
-- see warren.secrets.ssm_store). Isolated per-owner: `owner_id` is the user who
-- created the secret, and a workspace only ever sees its OWNER's own secrets —
-- never another user's. No permission-tier column (removed 2026-10-13): which
-- secrets a given workspace gets is an explicit by-name allow-list from the
-- resolved template's `secrets` field, not a tier filter — see
-- warren.secrets.store.resolve_secrets_for_names. Matches the SSM mirror's path
-- convention /{resource_prefix}/{server_id}/{owner_id}/{name} exactly so the
-- two backends stay interchangeable from routes/secrets.py's point of view.
CREATE TABLE IF NOT EXISTS secrets (
    secret_id    TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL,
    name         TEXT NOT NULL,
    ciphertext   BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    UNIQUE(owner_id, name)
);

-- AI9: machine tokens scoped to exactly one workspace, for processes inside it
-- calling back (supervisors, MCP callers). Always expiring; optionally bound to
-- an Ed25519 public key (proof-of-possession on every request). Resolution joins
-- `workspaces`, so a token dies with its workspace however that is destroyed.
CREATE TABLE IF NOT EXISTS workspace_tokens (
    token_id             TEXT PRIMARY KEY,
    workspace_id         TEXT NOT NULL,
    user_id              TEXT NOT NULL REFERENCES users(user_id),
    hashed_token         TEXT NOT NULL UNIQUE,
    public_key           TEXT,
    created_at           TEXT NOT NULL,
    expires_at           TEXT NOT NULL,
    revoked_at           TEXT,
    created_by_token_id  TEXT,
    provision_grant      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_workspace_tokens_workspace ON workspace_tokens(workspace_id);
