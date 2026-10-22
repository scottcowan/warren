# Changesets

This directory holds pending version-bump declarations for the `warren` workspace's packages
(`warren-cli`, `warren-common`, `warren-sidecar`, `warren-server`). It replaces hand-editing
`version = "..."` in each package's `pyproject.toml`.

## Adding a changeset

Every PR that changes a package's released behavior adds one changeset file describing which
package(s) changed and how severely, using semver rules:

- **major** — breaking change (removed/renamed public API, incompatible behavior change)
- **minor** — new backwards-compatible functionality
- **patch** — bug fix, docs, internal refactor with no behavior change visible to consumers

```bash
scripts/changeset.py add --bump warren-server:patch -m "Fix EFS access points never carrying the tag IAM conditions require"
scripts/changeset.py add --bump warren-server:minor --bump warren-common:patch -m "Add ecs_resource_prefix setting; warren-common gains the shared default"
```

Each invocation writes one `.changeset/<slug>.md` file:

```markdown
---
warren-server: patch
---

Fix EFS access points never carrying the tag IAM conditions require
```

A changeset can declare a bump for more than one package (one `--bump pkg:type` per package) if
a single change affects several packages at once — the exact situation that otherwise forces an
atomic cross-repo change into disconnected, hand-tracked version bumps (see the dep-coupling /
contract-drift audit this process grew out of).

Commit the changeset file(s) alongside your code change, in the same PR.

## Checking what's pending

```bash
scripts/changeset.py status
```

Shows every package with a pending changeset, the resulting next version, and which changeset
files contribute to it — without touching anything.

## Cutting a release

```bash
scripts/changeset.py version
```

For every package with at least one pending changeset:

1. Computes the new version (highest-severity bump among that package's changesets: major beats
   minor beats patch).
2. Writes the new version into that package's `pyproject.toml`.
3. Prepends a dated entry to that package's `CHANGELOG.md`, grouped by bump type, using each
   changeset's message.
4. Deletes the consumed `.changeset/*.md` files.
5. Runs `uv lock` to pick up the new versions in the workspace lockfile.

Review the diff, commit it (`git commit -m "chore: version packages"`), then tag and push as
usual — `.github/workflows/warren-server-image.yml` builds on `warren-server-v*.*.*` tags;
`warren-docker-base-image.yml` builds on `v*.*.*` tags for the shared base image.
