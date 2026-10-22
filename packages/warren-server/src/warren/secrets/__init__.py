"""warren.secrets — server-side secret store.

Two backends, selected by `settings.runtime_type` (see routes/secrets.py):
  - local (podman/docker): Fernet-encrypted rows in the shared SQLite db,
    keyed from WARREN_SECRET_KEY (`cipher.py` + `store.py`).
  - ecs: AWS SSM Parameter Store, SecureString — AWS's own KMS-backed
    encryption at rest, never a locally-held key (`ssm_store.py`). This is
    the write-side counterpart to runtime/ecs.py's long-standing read-only
    SSM lookup used at provision time.

Both are keyed by (owner_id, name) — see schema.sql's comment on the
`secrets` table for why. Which secrets a given workspace actually gets is an
explicit by-name allow-list from the resolved template's `secrets` field, not
a permission tier (tiers removed 2026-10-13, see store.py's module docstring).
"""

from __future__ import annotations
