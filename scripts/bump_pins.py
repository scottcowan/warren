#!/usr/bin/env python3
"""Check pinned harness/tool versions in warren's image Dockerfiles against upstream (AI6).

Pure stdlib, like changeset.py, so the weekly workflow runs it without `uv sync`.

What it checks:
    claude-code   Every Claude Code pin in images/*/Dockerfile and
                  packages/warren-server/images/*/Dockerfile:
                    - npm:     ``@anthropic-ai/claude-code@X.Y.Z``
                    - native:  ``claude.ai/install.sh | bash -s X.Y.Z``
                    - ARG:     ``ARG CLAUDE_CODE_VERSION=X.Y.Z``
                  Upstream = the npm dist-tag (``stable`` by default, the same
                  channel the native installer defaults to). A bump is only
                  proposed if the native release manifest for that version
                  exists, because the ECS dev base verifies the binary against
                  that signed manifest at build time. No static checksum is
                  pinned for Claude Code (the build verifies against the signed
                  manifest), so a bump is version-only.
    github-ssh    packages/warren-server/images/ecs-base/ssh_known_hosts (#29)
                  vs ``ssh_keys`` from https://api.github.com/meta.

Usage:
    scripts/bump_pins.py                 # report only, exit 0
    scripts/bump_pins.py --write         # rewrite the pins in place
    scripts/bump_pins.py --write --summary PATH --smoke-workflows PATH

With --smoke-workflows, writes the file names of the smoke workflows whose
``paths:`` filter covers a changed image directory (one per line), so the
workflow can dispatch them against the bump branch.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE_GLOBS = ("images/*/Dockerfile", "packages/warren-server/images/*/Dockerfile")
KNOWN_HOSTS = Path("packages/warren-server/images/ecs-base/ssh_known_hosts")
WORKFLOWS_DIR = Path(".github/workflows")

NPM_DIST_TAGS_URL = "https://registry.npmjs.org/-/package/@anthropic-ai/claude-code/dist-tags"
CLAUDE_MANIFEST_URL = "https://downloads.claude.ai/claude-code-releases/{version}/manifest.json"
GITHUB_META_URL = "https://api.github.com/meta"

_SEMVER = r"(\d+\.\d+\.\d+)"
CLAUDE_PIN_PATTERNS = (
    re.compile(r"(@anthropic-ai/claude-code@)" + _SEMVER),
    re.compile(r"(claude\.ai/install\.sh \| bash -s )" + _SEMVER),
    re.compile(r"(ARG CLAUDE_CODE_VERSION=)" + _SEMVER),
)
_SSH_KEY = re.compile(r"(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa) [A-Za-z0-9+/]+={0,2}")

# fetch(url) -> (status, body). Injected in tests; never raises for HTTP errors.
Fetcher = Callable[[str], "tuple[int, bytes]"]


def http_fetch(url: str) -> "tuple[int, bytes]":
    req = urllib.request.Request(url, headers={"User-Agent": "warren-bump-pins", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 -- fixed https URLs above
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def parse_version(v: str) -> "tuple[int, int, int]":
    major, minor, patch = (int(p) for p in v.split("."))
    return major, minor, patch


@dataclass
class Pin:
    path: Path  # relative to repo root
    line: int
    version: str


@dataclass
class Change:
    kind: str  # "claude-code" | "github-ssh"
    path: Path
    old: str
    new: str


def dockerfiles(root: Path) -> list[Path]:
    found: set[Path] = set()
    for pattern in DOCKERFILE_GLOBS:
        found.update(p.relative_to(root) for p in root.glob(pattern))
    return sorted(found)


def find_claude_pins(root: Path) -> list[Pin]:
    pins: list[Pin] = []
    for rel in dockerfiles(root):
        for lineno, line in enumerate((root / rel).read_text().splitlines(), start=1):
            for pat in CLAUDE_PIN_PATTERNS:
                for m in pat.finditer(line):
                    pins.append(Pin(rel, lineno, m.group(2)))
    return pins


def latest_claude_version(fetch: Fetcher, channel: str) -> Optional[str]:
    status, body = fetch(NPM_DIST_TAGS_URL)
    if status != 200:
        return None
    tags = json.loads(body)
    version = tags.get(channel) or tags.get("latest")
    if not version or not re.fullmatch(_SEMVER, version):
        return None
    return version


def claude_manifest_exists(fetch: Fetcher, version: str) -> bool:
    status, _ = fetch(CLAUDE_MANIFEST_URL.format(version=version))
    return status == 200


def bump_claude(root: Path, fetch: Fetcher, channel: str, write: bool) -> "tuple[list[Change], list[str]]":
    notes: list[str] = []
    pins = find_claude_pins(root)
    if not pins:
        return [], ["claude-code: no pins found"]
    latest = latest_claude_version(fetch, channel)
    if latest is None:
        return [], [f"claude-code: could not read npm dist-tag {channel!r}; skipped"]
    stale = [p for p in pins if parse_version(p.version) < parse_version(latest)]
    if not stale:
        return [], [f"claude-code: all {len(pins)} pins at or above {latest}"]
    if not claude_manifest_exists(fetch, latest):
        return [], [f"claude-code: {latest} has no native release manifest yet; skipped"]

    changes: list[Change] = []
    for rel in sorted({p.path for p in stale}):
        text = (root / rel).read_text()
        olds = sorted({p.version for p in stale if p.path == rel})

        def _sub(m: "re.Match[str]") -> str:
            ver = m.group(2)
            return m.group(1) + (latest if parse_version(ver) < parse_version(latest) else ver)

        new_text = text
        for pat in CLAUDE_PIN_PATTERNS:
            new_text = pat.sub(_sub, new_text)
        if new_text != text:
            if write:
                (root / rel).write_text(new_text)
            changes.append(Change("claude-code", rel, ", ".join(olds), latest))
    return changes, notes


def parse_known_hosts(text: str) -> "set[str]":
    """Return the set of ``<keytype> <base64>`` entries for github.com."""
    keys: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.lstrip().startswith("#") and "github.com" in parts[0].split(","):
            keys.add(f"{parts[1]} {parts[2]}")
    return keys


def bump_github_ssh(root: Path, fetch: Fetcher, write: bool) -> "tuple[list[Change], list[str]]":
    path = root / KNOWN_HOSTS
    if not path.exists():
        return [], [f"github-ssh: {KNOWN_HOSTS} not found; skipped"]
    status, body = fetch(GITHUB_META_URL)
    if status != 200:
        return [], [f"github-ssh: GET {GITHUB_META_URL} returned {status}; skipped"]
    upstream = [k.strip() for k in json.loads(body).get("ssh_keys", []) if k.strip()]
    if not upstream:
        return [], ["github-ssh: api.github.com/meta returned no ssh_keys; skipped"]
    if not all(_SSH_KEY.fullmatch(k) for k in upstream):
        return [], ["github-ssh: api.github.com/meta returned a malformed key; skipped"]
    current = parse_known_hosts(path.read_text())
    if current == set(upstream):
        return [], [f"github-ssh: {len(upstream)} host keys match api.github.com/meta"]
    if write:
        path.write_text("".join(f"github.com {k}\n" for k in upstream))
    removed = sorted(k.split()[0] for k in current - set(upstream))
    added = sorted(k.split()[0] for k in set(upstream) - current)
    return [Change("github-ssh", KNOWN_HOSTS, "removed: " + (", ".join(removed) or "none"),
                   "added: " + (", ".join(added) or "none"))], []


def smoke_workflows_for(root: Path, changed: list[Path]) -> list[str]:
    """Smoke workflows whose path filters cover a changed file's image directory."""
    out: list[str] = []
    for wf in sorted((root / WORKFLOWS_DIR).glob("*-smoke.yml")):
        text = wf.read_text()
        if any(f"{c.parent.as_posix()}/**" in text for c in changed):
            out.append(wf.name)
    return out


def render_summary(changes: list[Change], notes: list[str]) -> str:
    lines = ["Automated weekly pin check (AI6, `scripts/bump_pins.py`).", ""]
    if changes:
        lines += ["| Pin | File | Old | New |", "|---|---|---|---|"]
        lines += [f"| {c.kind} | `{c.path.as_posix()}` | {c.old} | {c.new} |" for c in changes]
        lines.append("")
    if notes:
        lines += [f"- {n}" for n in notes]
        lines.append("")
    if any(c.kind == "github-ssh" for c in changes):
        lines += [
            "**GitHub SSH host keys changed.** Confirm against "
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints "
            "before merging: a host-key change is either a GitHub rotation or an attack on this job.",
            "",
        ]
    lines += [
        "Merge only after the dispatched smoke tests pass on this branch. Images that FROM a "
        "bumped image by digest (warren-agent-base, warren-ecs-agent-base) need a publish + digest "
        "bump afterwards.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None, fetch: Fetcher = http_fetch, root: Path = REPO_ROOT) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help="rewrite pins in place")
    ap.add_argument("--channel", default="stable", help="npm dist-tag for Claude Code (default: stable)")
    ap.add_argument("--summary", type=Path, help="write a markdown PR body here")
    ap.add_argument("--smoke-workflows", type=Path, help="write affected smoke workflow names here")
    args = ap.parse_args(argv)

    changes, notes = bump_claude(root, fetch, args.channel, args.write)
    ssh_changes, ssh_notes = bump_github_ssh(root, fetch, args.write)
    changes += ssh_changes
    notes += ssh_notes

    summary = render_summary(changes, notes)
    print(summary)
    if args.summary:
        args.summary.write_text(summary)
    if args.smoke_workflows:
        wfs = smoke_workflows_for(root, [c.path for c in changes])
        args.smoke_workflows.write_text("".join(f"{w}\n" for w in wfs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
