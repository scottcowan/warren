#!/usr/bin/env python3
"""Release PRs for warren's published images.

Pure stdlib, like bump_pins.py, so the release workflow runs it without `uv sync`.

.github/releases.json lists each image's current version and every path its
build reads (``paths``, minus ``exclude``; a trailing ``/`` means a directory).
An image is pending when a commit since its last release tag
(``<name>-v<version>`` if it is an ancestor of HEAD, else ``baseline``) touches one of
those paths. The bump is the largest any of those commits asks for: ``!`` after
the type or a ``BREAKING CHANGE:`` footer is major, ``feat`` is minor, anything
else is patch.

Usage:
    scripts/release.py plan                          # print pending releases
    scripts/release.py prepare --title PATH --body PATH
                                                     # bump releases.json, prepend CHANGELOG.md
    scripts/release.py released --before REV         # {"name": "tag"} for versions changed since REV
    scripts/release.py notes NAME                    # CHANGELOG.md section for NAME's version
    scripts/release.py check                         # every Dockerfile COPY/ADD source is in paths

``check`` keeps ``paths`` honest: each image's ``dockerfile`` and every local
COPY/ADD source (relative to ``context``) must be covered. A whole-context
``COPY .`` can't be checked, so warren-server's paths are kept by hand.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG = Path(".github/releases.json")
CHANGELOG = Path("CHANGELOG.md")
CHANGELOG_HEADER = "# Changelog\n\nImage releases, newest first. Written by scripts/release.py.\n\n"

PATCH, MINOR, MAJOR = 0, 1, 2
_SUBJECT_RE = re.compile(r"^(?P<type>[A-Za-z]+)(?:\([^)]*\))?(?P<bang>!)?:")
_BREAKING_RE = re.compile(r"^BREAKING[ -]CHANGE:", re.MULTILINE)
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_COPY_RE = re.compile(r"^(?:COPY|ADD)\s+(.*)$", re.IGNORECASE)
_FLAG_RE = re.compile(r"^--(\S+)\s*")


class ReleaseError(Exception):
    pass


@dataclass
class Commit:
    sha: str
    subject: str
    body: str
    files: list[str]


@dataclass
class Pending:
    name: str
    current: str
    next: str
    commits: list[Commit] = field(default_factory=list)


def git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=check)


def load_config(root: Path) -> dict:
    return json.loads((root / CONFIG).read_text())


def write_config(root: Path, config: dict) -> None:
    (root / CONFIG).write_text(json.dumps(config, indent=2) + "\n")


def tag_name(name: str, version: str) -> str:
    return f"{name}-v{version}"


def bump_kind(commit: Commit) -> int:
    m = _SUBJECT_RE.match(commit.subject)
    if (m and m.group("bang")) or _BREAKING_RE.search(commit.body):
        return MAJOR
    if m and m.group("type").lower() == "feat":
        return MINOR
    return PATCH


def next_version(version: str, kind: int) -> str:
    m = _VERSION_RE.match(version)
    if not m:
        raise ReleaseError(f"version {version!r} is not X.Y.Z")
    major, minor, patch = (int(g) for g in m.groups())
    if kind == MAJOR:
        return f"{major + 1}.0.0"
    if kind == MINOR:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _matches(path: str, prefixes: list[str]) -> bool:
    return any(path.startswith(p) if p.endswith("/") else path == p for p in prefixes)


def touches(component: dict, files: list[str]) -> bool:
    exclude = component.get("exclude", [])
    return any(_matches(f, component["paths"]) and not _matches(f, exclude) for f in files)


def commits_since(root: Path, base: str) -> list[Commit]:
    out = git(root, "log", "--format=%x1e%H%x1f%s%x1f%b%x1f", "--name-only", f"{base}..HEAD").stdout
    commits = []
    for record in out.split("\x1e")[1:]:
        sha, subject, body, files = record.split("\x1f", 3)
        commits.append(Commit(sha, subject, body.strip(), [f for f in files.splitlines() if f]))
    return commits


def release_base(root: Path, config: dict, name: str) -> str:
    tag = tag_name(name, config["components"][name]["version"])
    if git(root, "merge-base", "--is-ancestor", f"refs/tags/{tag}", "HEAD", check=False).returncode == 0:
        return tag
    return config["baseline"]


def plan(root: Path, config: dict) -> list[Pending]:
    pending = []
    for name, component in config["components"].items():
        base = release_base(root, config, name)
        hits = [c for c in commits_since(root, base) if touches(component, c.files)]
        if hits:
            kind = max(bump_kind(c) for c in hits)
            pending.append(Pending(name, component["version"], next_version(component["version"], kind), hits))
    return pending


def changelog_section(p: Pending, date: str) -> str:
    lines = [f"## {p.name} {p.next} ({date})", ""]
    lines += [f"- {c.subject} ({c.sha[:7]})" for c in p.commits]
    return "\n".join(lines) + "\n\n"


def prepend_changelog(root: Path, sections: str) -> None:
    path = root / CHANGELOG
    existing = path.read_text() if path.exists() else CHANGELOG_HEADER
    rest = existing[len(CHANGELOG_HEADER):] if existing.startswith(CHANGELOG_HEADER) else existing
    path.write_text(CHANGELOG_HEADER + sections + rest)


def pr_title(pending: list[Pending]) -> str:
    return "release: " + ", ".join(f"{p.name} {p.next}" for p in pending)


def pr_body(pending: list[Pending], date: str) -> str:
    intro = (
        "Merging this tags each image below and publishes it. "
        "The release workflow keeps this PR up to date as commits land on main.\n\n"
    )
    return intro + "".join(changelog_section(p, date) for p in pending)


def prepare(root: Path, today: str) -> list[Pending]:
    config = load_config(root)
    pending = plan(root, config)
    if pending:
        for p in pending:
            config["components"][p.name]["version"] = p.next
        write_config(root, config)
        prepend_changelog(root, "".join(changelog_section(p, today) for p in pending))
    return pending


def released(root: Path, before: str) -> dict[str, str]:
    shown = git(root, "show", f"{before}:{CONFIG.as_posix()}", check=False)
    if shown.returncode != 0:
        return {}
    old = json.loads(shown.stdout)["components"]
    new = load_config(root)["components"]
    return {
        name: tag_name(name, c["version"])
        for name, c in new.items()
        if name in old and old[name]["version"] != c["version"]
    }


def notes(root: Path, name: str) -> str:
    version = load_config(root)["components"][name]["version"]
    heading = f"## {name} {version} ("
    text = (root / CHANGELOG).read_text() if (root / CHANGELOG).exists() else ""
    out, inside = [], False
    for line in text.splitlines():
        if line.startswith("## "):
            if inside:
                break
            inside = line.startswith(heading)
            continue
        if inside:
            out.append(line)
    return "\n".join(out).strip() + "\n"


def dockerfile_sources(text: str) -> list[str]:
    sources = []
    for line in re.sub(r"\\\n", " ", text).splitlines():
        m = _COPY_RE.match(line.strip())
        if not m:
            continue
        rest, flags = m.group(1).strip(), []
        while (f := _FLAG_RE.match(rest)):
            flags.append(f.group(1))
            rest = rest[f.end():]
        if any(flag.startswith("from=") for flag in flags):
            continue
        args = json.loads(rest) if rest.startswith("[") else rest.split()
        sources += [s for s in args[:-1] if "://" not in s]
    return sources


def uncovered(root: Path, component: dict) -> list[str]:
    exclude = component.get("exclude", [])
    text = (root / component["dockerfile"]).read_text()
    candidates = [component["dockerfile"]]
    candidates += [os.path.normpath(os.path.join(component["context"], s)) for s in dockerfile_sources(text)]
    missing = []
    for src in candidates:
        if src == ".":
            continue
        covered = any(src == p or (p.endswith("/") and f"{src}/".startswith(p)) for p in component["paths"])
        if not covered or _matches(src, exclude):
            missing.append(src)
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan")
    prep = sub.add_parser("prepare")
    prep.add_argument("--title", type=Path, required=True)
    prep.add_argument("--body", type=Path, required=True)
    rel = sub.add_parser("released")
    rel.add_argument("--before", required=True)
    note = sub.add_parser("notes")
    note.add_argument("name")
    sub.add_parser("check")
    args = parser.parse_args(argv)

    try:
        if args.cmd == "plan":
            for p in plan(REPO_ROOT, load_config(REPO_ROOT)):
                print(f"{p.name}: {p.current} -> {p.next} ({len(p.commits)} commits)")
        elif args.cmd == "prepare":
            today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
            pending = prepare(REPO_ROOT, today)
            args.title.write_text(pr_title(pending) if pending else "")
            args.body.write_text(pr_body(pending, today) if pending else "")
        elif args.cmd == "released":
            print(json.dumps(released(REPO_ROOT, args.before)))
        elif args.cmd == "notes":
            sys.stdout.write(notes(REPO_ROOT, args.name))
        elif args.cmd == "check":
            failed = False
            for name, component in load_config(REPO_ROOT)["components"].items():
                for src in uncovered(REPO_ROOT, component):
                    print(f"{name}: {src} is a build input but not in its paths in {CONFIG}", file=sys.stderr)
                    failed = True
            if failed:
                return 1
            print("release: every image's build inputs are in its paths")
    except (ReleaseError, subprocess.CalledProcessError) as e:
        print(f"release: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
