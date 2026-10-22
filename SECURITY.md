# Security Policy

Warren provisions isolated, permission-scoped environments and brokers secrets into
them. Bugs here can mean cross-workspace secret leakage, scope-boundary bypass, or
privilege escalation inside a provisioned container — please report responsibly.

## Reporting a vulnerability

**Do not open a public issue for a security report.** Instead, use GitHub's private
vulnerability reporting:

1. Go to the [Security tab](https://github.com/scottcowan/warren/security) of this
   repository.
2. Click **Report a vulnerability**.
3. Include what you found, how to reproduce it, and the worst-case impact as you
   understand it.

You'll get an initial response within a few days. If the report is confirmed, a fix
will be prepared privately and disclosed once a patched version is available.

## Scope

In scope:
- `warren` CLI and `warren-common` (this repo)
- `warren-sidecar` (in-workspace agent)
- `warren-server` (`packages/warren-server/`)
- The container images under `images/` and `packages/warren-server/images/`

Out of scope:
- Vulnerabilities in a third-party base image's own upstream packages (report those
  upstream — Debian, Alpine, etc.) unless warren's own build pulls in a specific
  pinned vulnerable version.
- Issues that require an attacker to already have admin-level control of a warren
  server instance's host.

## Threat model

[docs/threat-model.md](docs/threat-model.md) lists the assets, the trust boundary of each
runtime (seatbelt, bubblewrap, nsjail, docker/podman, ECS Fargate), the control that covers
each threat, and the known residual risks. A report that breaks one of those controls is
in scope; a residual risk listed there is known.

## Known limitations

These are deliberate, currently-accepted tradeoffs, not bugs to report:

- **The GitHub App repo allow-list (`WARREN_GITHUB_APP_ALLOWED_REPOS`) is
  deployment-wide, not per-user.** It narrows a minted installation token down to a
  known repo set; it does not add per-user authorization on top. Every authenticated
  user on a given warren-server instance can mint a token (and clone) for every repo
  named in that allow-list — the same trust level as any other authenticated-user
  capability in this codebase. A deployment that needs per-user repo access control
  should run one warren-server instance per trust boundary.
- **Local seatbelt (macOS) sandboxing is not a security boundary against a hostile
  agent, only a mistake-containment measure.** It restricts accidental filesystem
  writes outside a workspace, but several known escapes remain unrestricted by
  design tradeoff (browser-OAuth flows need `lsopen`, which can launch arbitrary
  apps outside the sandbox; `mach-lookup`/`mach-register`, `iokit-open`, and
  `distributed-notification-post` are also unrestricted). Do not run an agent you
  don't trust against a local seatbelt workspace expecting host isolation.

## Maintainer checklist: before going public, and before each release

Repository settings that the code can't enforce. Check them before the repo is made
public, and again before tagging a release:

- [ ] **Tag ruleset** on `warren-*-v*` tags: only maintainers can create them; no
      update or deletion. Release and image-publish workflows trust these tags.
- [ ] **Branch ruleset** on `main`: pull request required with an approving review,
      required status checks (package test suites and `public hygiene`), no force
      pushes, no deletion.
- [ ] **Secret scanning and push protection** enabled.
- [ ] **Private vulnerability reporting** enabled (the reporting flow above depends on it).
- [ ] **Fork pull request workflows** require approval for all outside contributors.
- [ ] `python3 scripts/check_public_hygiene.py --history` and the gitleaks history scan
      (`.github/workflows/public-hygiene.yml`) are clean on the commit being published.
