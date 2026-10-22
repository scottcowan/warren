#!/usr/bin/env python3
"""Pre-public hygiene check: find things that must not ship in a public repo.

Scans tracked files (default) or, with --history, every commit reachable from
HEAD (author/committer identity, commit message, and added diff lines) for:

  denylist          a token whose sha256 is in scripts/public_hygiene_denylist.txt
  aws-account-id    a 12-digit AWS account id in an ARN/account context that is
                    not a known dummy id (123456789012 etc.)
  aws-sso-portal    an IAM Identity Center start-portal URL
  aws-sso-role      an Identity Center role name with a real 16-hex suffix
  home-path         an absolute /Users/<name> or /home/<name> path for a name
                    that is not a generic placeholder (me, user, ...)
  gist-url          a gist URL with an id (private gists are unlisted, not secret)

Findings print as path:line: rule (history: <sha>:path:line: rule). The matched
text is not printed, so a CI log doesn't re-leak it. Exit 1 if anything is found.

Stdlib only. Run: python3 scripts/check_public_hygiene.py [--history]
Tests: python3 -m unittest discover -s scripts/tests
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DENYLIST_PATH = REPO_ROOT / "scripts" / "public_hygiene_denylist.txt"
# The denylist holds only hashes, but skip it anyway so a short hash can never
# be mistaken for an id.
EXCLUDED_PATHS = {"scripts/public_hygiene_denylist.txt"}

DUMMY_ACCOUNT_IDS = {
    "123456789012",
    "000000000000",
    "111111111111",
    "222222222222",
    "999999999999",
    "012345678901",
    "210987654321",
}
GENERIC_HOME_NAMES = {
    "me", "user", "username", "you", "your-name", "yourname", "name", "op",
    "warren", "runner", "agent", "ubuntu", "root", "dev", "developer",
    "alice", "bob", "example", "jdoe", "someone", "test", "node", "app", "...",
}

_ACCOUNT_PATTERNS = [
    re.compile(r"arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:(\d{12})(?!\d)"),
    re.compile(r"(?<!\d)(\d{12})\.dkr\.ecr\."),
    re.compile(r"(?i)account[_ .-]?(?:id)?[\"']?\s*[:=]\s*[\"']?(\d{12})(?!\d)"),
    re.compile(r"(?i)--account(?:-id)?[ =](\d{12})(?!\d)"),
]
# Written so these source lines don't match themselves.
_SSO_PORTAL = re.compile(r"(?i)\.aws[a]pps\.com/start")
_SSO_ROLE = re.compile(r"AWSReserved[S]SO_[A-Za-z0-9+=,.@-]+_[0-9a-f]{16}(?![0-9a-f])")
_HOME_PATH = re.compile(r"(?<![A-Za-z0-9_.-])/(?:Users|home)/([A-Za-z0-9._-]+)")
_GIST = re.compile(r"(?i)gist\.github(?:usercontent)?\.com/(?:[A-Za-z0-9-]+/)?[0-9a-f]{20,}")
_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class Finding:
    location: str
    line: int
    rule: str

    def __str__(self) -> str:
        return f"{self.location}:{self.line}: {self.rule}"


def load_denylist(path: Path = DENYLIST_PATH) -> frozenset[str]:
    hashes = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if s and not s.startswith("#"):
            if not re.fullmatch(r"[0-9a-f]{64}", s):
                raise ValueError(f"{path}: not a sha256 hex digest: {s[:12]}...")
            hashes.add(s)
    return frozenset(hashes)


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _denylisted(line: str, denylist: frozenset[str]) -> bool:
    low = line.lower()
    words = [(m.group(), m.start(), m.end()) for m in _WORD.finditer(low)]
    for i, (w, _, end) in enumerate(words):
        if _sha(w) in denylist:
            return True
        if i + 1 < len(words):
            nxt, nstart, _ = words[i + 1]
            # adjacent words joined by one separator: "a-b", "a_b", "a.b", "a b"
            if nstart == end + 1 and low[end] in "-_. /" and _sha(f"{w}-{nxt}") in denylist:
                return True
    return False


def scan_line(line: str, denylist: frozenset[str]) -> list[str]:
    """Return the rule names that fire on one line of text."""
    rules = []
    if denylist and _denylisted(line, denylist):
        rules.append("denylist")
    for pat in _ACCOUNT_PATTERNS:
        if any(m.group(1) not in DUMMY_ACCOUNT_IDS for m in pat.finditer(line)):
            rules.append("aws-account-id")
            break
    if _SSO_PORTAL.search(line):
        rules.append("aws-sso-portal")
    if _SSO_ROLE.search(line):
        rules.append("aws-sso-role")
    if any(m.group(1).lower() not in GENERIC_HOME_NAMES for m in _HOME_PATH.finditer(line)):
        rules.append("home-path")
    if _GIST.search(line):
        rules.append("gist-url")
    return rules


def scan_text(location: str, text: str, denylist: frozenset[str], first_line: int = 1) -> list[Finding]:
    out = []
    for n, line in enumerate(text.splitlines(), start=first_line):
        out.extend(Finding(location, n, r) for r in scan_line(line, denylist))
    return out


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    ).stdout


def scan_tree(repo: Path, denylist: frozenset[str]) -> list[Finding]:
    findings = []
    for rel in _git(repo, "ls-files", "-z").split("\0"):
        if not rel or rel in EXCLUDED_PATHS:
            continue
        p = repo / rel
        if not p.is_file() or p.is_symlink():
            continue
        data = p.read_bytes()
        if b"\0" in data[:8192]:
            continue  # binary
        findings.extend(scan_text(rel, data.decode("utf-8", errors="replace"), denylist))
    return findings


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def scan_history(repo: Path, denylist: frozenset[str], rev: str = "HEAD") -> list[Finding]:
    findings = []
    meta = _git(repo, "log", "--format=%H%x1f%an <%ae>%x1f%cn <%ce>%x1f%B%x1e", rev)
    for rec in meta.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, author, committer, body = rec.split("\x1f", 3)
        short = sha[:12]
        for r in scan_line(author, denylist):
            findings.append(Finding(f"{short}:<author>", 0, r))
        for r in scan_line(committer, denylist):
            findings.append(Finding(f"{short}:<committer>", 0, r))
        findings.extend(scan_text(f"{short}:<message>", body, denylist))

    diff = _git(repo, "log", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-renames",
                "--format=%x00%H", rev)
    sha, path, lineno = "", None, 0
    for line in diff.splitlines():
        if line.startswith("\0"):
            sha, path = line[1:13], None
        elif line.startswith("+++ "):
            target = line[4:]
            path = None if target == "/dev/null" else target[2:] if target.startswith("b/") else target
        elif line.startswith("@@"):
            m = _HUNK.match(line)
            lineno = int(m.group(1)) if m else 0
        elif line.startswith("+") and path is not None:
            if path not in EXCLUDED_PATHS:
                findings.extend(Finding(f"{sha}:{path}", lineno, r) for r in scan_line(line[1:], denylist))
            lineno += 1
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--history", action="store_true", help="scan every commit reachable from HEAD")
    ap.add_argument("--repo", type=Path, default=REPO_ROOT)
    args = ap.parse_args(argv)
    denylist = load_denylist()
    findings = scan_history(args.repo, denylist) if args.history else scan_tree(args.repo, denylist)
    for f in findings:
        print(f)
    scope = "history" if args.history else "tracked files"
    if findings:
        print(f"public-hygiene: {len(findings)} finding(s) in {scope}", file=sys.stderr)
        return 1
    print(f"public-hygiene: {scope} clean", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
