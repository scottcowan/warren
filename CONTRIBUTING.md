# Contributing

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Bug fixes

PRs for bug fixes are welcome directly — no need to file an issue first. Include a
short description of the bug and, where practical, a test that fails without the fix.

## Features

Open an issue before sending a PR. Describe the problem you're trying to solve and
your proposed approach; this project has fairly opinionated boundaries (see each
package's README for what it does and doesn't do), and it's much cheaper to align on
scope and design before code is written than after. A PR that implements a
not-yet-discussed feature may be asked to split out into an issue first.

## Everything else

Bug reports, questions, and design discussion are all welcome as issues, whether or
not you plan to open a PR yourself.

## Development

```bash
git clone https://github.com/scottcowan/warren.git
cd warren
uv sync
uv run --package warren-server pytest packages/warren-server/tests/unit -q
```

This is a `uv` workspace with no root-level project of its own — `packages/warren-cli`,
`packages/warren-common`, `packages/warren-sidecar`, and `packages/warren-server` are
independently versioned members. Use `uv run --package <name> pytest <path>` to run
tests scoped to one package.

## Public hygiene

`.github/workflows/public-hygiene.yml` runs gitleaks (config: `.gitleaks.toml`) and
`scripts/check_public_hygiene.py`, which rejects internal names, real AWS account ids,
SSO portal URLs, personal home-directory paths and gist links. Run it before pushing:

```bash
python3 scripts/check_public_hygiene.py            # tracked files
python3 scripts/check_public_hygiene.py --history  # every commit reachable from HEAD
python3 -m unittest discover -s scripts/tests
```

Use generic examples (`acme-api`, `example-app`, `/Users/me`, account `123456789012`).
The denylist (`scripts/public_hygiene_denylist.txt`) stores sha256 hashes, not the
tokens themselves. Gitleaks allowlist entries must match both a path and the exact
fixture value. Maintainers: see the release checklist in [SECURITY.md](SECURITY.md).

## Versioning

Each package is versioned independently via `scripts/changeset.py` — see that file's
docstring for the patch/minor/major changeset workflow. Don't hand-edit a package's
version in `pyproject.toml`.
