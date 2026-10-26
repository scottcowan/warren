"""warren.secrets — server-side secret store.

Fernet-encrypted rows in the shared SQLite db, keyed from WARREN_SECRET_KEY
(`cipher.py` + `store.py`), on every runtime. There is no second copy: podman
and docker workspaces get their secrets as container env, ECS tasks as a file on
their own EFS volume (runtime/ecs_secrets.py).

Keyed by (owner_id, name) — see schema.sql's comment on the `secrets` table for
why. Which secrets a given workspace actually gets is an explicit by-name
allow-list from the resolved template's `secrets` field, not a permission tier
(tiers removed 2026-10-13, see store.py's module docstring).
"""

from __future__ import annotations
