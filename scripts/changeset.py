#!/usr/bin/env python3
"""Changeset-based semver versioning for the warren uv workspace.

Pure stdlib — no dependency on the workspace's own venv, so it runs even before
`uv sync`. See .changeset/README.md for the user-facing workflow.

Subcommands:
    add      Write a new pending changeset file under .changeset/.
    status   Show pending changesets and the version bumps they'd produce.
    version  Consume all pending changesets: bump each affected package's
             pyproject.toml version, prepend to its CHANGELOG.md, delete the
             consumed changeset files, and re-lock the workspace.
"""

from __future__ import annotations

import argparse
import datetime
import random
import re
import string
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHANGESET_DIR = REPO_ROOT / ".changeset"
BUMP_SEVERITY = {"patch": 0, "minor": 1, "major": 2}
_VERSION_LINE_RE = re.compile(r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"\s*$', re.MULTILINE)
_WORKSPACE_MEMBERS_RE = re.compile(r'members\s*=\s*\[([^\]]*)\]')
_WORD_RE = re.compile(r'"([^"]+)"')


class ChangesetError(Exception):
    pass


def discover_packages() -> dict[str, Path]:
    """Return {package_name: path_to_pyproject.toml} for every workspace member."""
    root_pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    match = _WORKSPACE_MEMBERS_RE.search(root_pyproject)
    if not match:
        raise ChangesetError("could not find [tool.uv.workspace] members in root pyproject.toml")
    member_paths = _WORD_RE.findall(match.group(1))

    packages: dict[str, Path] = {}
    for member in member_paths:
        pyproject_path = REPO_ROOT / member / "pyproject.toml"
        text = pyproject_path.read_text()
        name_match = re.search(r'^name\s*=\s*"([^"]+)"\s*$', text, re.MULTILINE)
        if not name_match:
            raise ChangesetError(f"{pyproject_path} has no [project] name field")
        packages[name_match.group(1)] = pyproject_path
    return packages


def read_version(pyproject_path: Path) -> tuple[int, int, int]:
    text = pyproject_path.read_text()
    match = _VERSION_LINE_RE.search(text)
    if not match:
        raise ChangesetError(f"{pyproject_path} has no version = \"X.Y.Z\" line")
    return tuple(int(g) for g in match.groups())  # type: ignore[return-value]


def write_version(pyproject_path: Path, new_version: tuple[int, int, int]) -> None:
    text = pyproject_path.read_text()
    new_text, count = _VERSION_LINE_RE.subn(
        f'version = "{new_version[0]}.{new_version[1]}.{new_version[2]}"', text, count=1
    )
    if count != 1:
        raise ChangesetError(f"failed to rewrite version in {pyproject_path}")
    pyproject_path.write_text(new_text)


def bump(version: tuple[int, int, int], bump_type: str) -> tuple[int, int, int]:
    major, minor, patch = version
    if bump_type == "major":
        return (major + 1, 0, 0)
    if bump_type == "minor":
        return (major, minor + 1, 0)
    if bump_type == "patch":
        return (major, minor, patch + 1)
    raise ChangesetError(f"unknown bump type {bump_type!r} (expected major/minor/patch)")


def parse_changeset(path: Path) -> tuple[dict[str, str], str]:
    """Return ({package: bump_type}, message) for one .changeset/*.md file."""
    text = path.read_text()
    parts = text.split("---")
    if len(parts) < 3:
        raise ChangesetError(f"{path} is missing --- frontmatter delimiters")
    frontmatter = parts[1]
    message = "---".join(parts[2:]).strip()

    bumps: dict[str, str] = {}
    for line in frontmatter.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            raise ChangesetError(f"{path}: malformed frontmatter line {line!r}")
        pkg, bump_type = line.split(":", 1)
        pkg, bump_type = pkg.strip(), bump_type.strip()
        if bump_type not in BUMP_SEVERITY:
            raise ChangesetError(f"{path}: unknown bump type {bump_type!r} for {pkg}")
        bumps[pkg] = bump_type
    if not bumps:
        raise ChangesetError(f"{path}: no package:bump-type pairs in frontmatter")
    return bumps, message


def pending_changesets() -> list[Path]:
    if not CHANGESET_DIR.is_dir():
        return []
    return sorted(p for p in CHANGESET_DIR.glob("*.md") if p.name != "README.md")


def compute_plan(
    packages: dict[str, Path],
) -> tuple[dict[str, tuple[str, list[tuple[Path, str]]]], list[Path]]:
    """Return ({package: (bump_type, [(changeset_path, message), ...])}, changeset_paths)."""
    files = pending_changesets()
    plan: dict[str, tuple[str, list[tuple[Path, str]]]] = {}
    for path in files:
        bumps, message = parse_changeset(path)
        for pkg, bump_type in bumps.items():
            if pkg not in packages:
                raise ChangesetError(f"{path}: {pkg!r} is not a known workspace package")
            existing = plan.get(pkg)
            if existing is None or BUMP_SEVERITY[bump_type] > BUMP_SEVERITY[existing[0]]:
                entries = (existing[1] if existing else []) + [(path, message)]
                plan[pkg] = (bump_type, entries)
            else:
                plan[pkg][1].append((path, message))
    return plan, files


def cmd_status(_args: argparse.Namespace) -> None:
    packages = discover_packages()
    plan, files = compute_plan(packages)
    if not files:
        print("No pending changesets.")
        return
    for pkg, (bump_type, entries) in sorted(plan.items()):
        current = read_version(packages[pkg])
        new = bump(current, bump_type)
        current_s = ".".join(map(str, current))
        new_s = ".".join(map(str, new))
        print(f"{pkg}: {current_s} -> {new_s} ({bump_type})")
        for path, message in entries:
            first_line = message.splitlines()[0] if message else "(no message)"
            print(f"    {path.name}: {first_line}")


def cmd_version(_args: argparse.Namespace) -> None:
    packages = discover_packages()
    plan, files = compute_plan(packages)
    if not files:
        print("No pending changesets — nothing to version.")
        return

    today = datetime.date.today().isoformat()  # noqa: DTZ011 — changelog date, local-tz is correct
    for pkg, (bump_type, entries) in sorted(plan.items()):
        pyproject_path = packages[pkg]
        current = read_version(pyproject_path)
        new = bump(current, bump_type)
        write_version(pyproject_path, new)

        changelog_path = pyproject_path.parent / "CHANGELOG.md"
        new_section = [f"## {'.'.join(map(str, new))} — {today}", ""]
        for _, message in entries:
            for line in (message or "(no description)").splitlines():
                new_section.append(f"- {line}" if line.strip() else line)
        new_section.append("")
        body = "\n".join(new_section)

        if changelog_path.exists():
            existing = changelog_path.read_text()
            if existing.startswith("# Changelog"):
                header, _, rest = existing.partition("\n")
                changelog_path.write_text(f"{header}\n\n{body}\n{rest.lstrip(chr(10))}")
            else:
                changelog_path.write_text(f"{body}\n{existing}")
        else:
            changelog_path.write_text(f"# Changelog\n\n{body}\n")

        print(f"{pkg}: {'.'.join(map(str, current))} -> {'.'.join(map(str, new))} ({bump_type})")

    for path in files:
        path.unlink()

    subprocess.run(["uv", "lock"], cwd=REPO_ROOT, check=True)
    print(f"\nConsumed {len(files)} changeset(s). Review the diff, then commit.")


def cmd_add(args: argparse.Namespace) -> None:
    bumps: dict[str, str] = {}
    for item in args.bump:
        if ":" not in item:
            raise ChangesetError(f"--bump {item!r} must be PACKAGE:TYPE")
        pkg, bump_type = item.split(":", 1)
        if bump_type not in BUMP_SEVERITY:
            raise ChangesetError(f"--bump {item!r}: type must be major, minor, or patch")
        bumps[pkg] = bump_type

    packages = discover_packages()
    unknown = sorted(set(bumps) - set(packages))
    if unknown:
        raise ChangesetError(f"unknown package(s): {', '.join(unknown)} (known: {', '.join(sorted(packages))})")

    CHANGESET_DIR.mkdir(exist_ok=True)
    slug = "".join(random.choices(string.ascii_lowercase, k=12))
    path = CHANGESET_DIR / f"{slug}.md"

    frontmatter = "\n".join(f"{pkg}: {bump_type}" for pkg, bump_type in bumps.items())
    path.write_text(f"---\n{frontmatter}\n---\n\n{args.message}\n")
    print(f"Wrote {path.relative_to(REPO_ROOT)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    add_parser = sub.add_parser("add", help="Create a new pending changeset")
    add_parser.add_argument(
        "--bump", action="append", required=True, metavar="PACKAGE:TYPE",
        help="e.g. --bump warren-server:patch (repeatable for multiple packages)",
    )
    add_parser.add_argument("-m", "--message", required=True, help="Changelog entry text")
    add_parser.set_defaults(func=cmd_add)

    status_parser = sub.add_parser("status", help="Show pending version bumps")
    status_parser.set_defaults(func=cmd_status)

    version_parser = sub.add_parser("version", help="Apply pending changesets")
    version_parser.set_defaults(func=cmd_version)

    args = parser.parse_args()
    try:
        args.func(args)
    except ChangesetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
