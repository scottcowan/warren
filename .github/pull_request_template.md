## What and why

<!-- What this changes and the problem it solves. Link the issue for features. -->

## How it was tested

<!-- Commands run, e.g. `uv run --package warren-server pytest packages/warren-server/tests/unit -q`. -->

## Checklist

- [ ] Tests added or updated for the change
- [ ] A changeset added for each package whose behaviour changed (`scripts/changeset.py`)
- [ ] Docs / `docs/threat-model.md` updated if a trust boundary, credential path or route changed
- [ ] No secrets, internal names, real account ids or personal paths (`python3 scripts/check_public_hygiene.py`)

<!-- Security issues: don't open a PR that discloses one. Use private vulnerability reporting (SECURITY.md). -->
