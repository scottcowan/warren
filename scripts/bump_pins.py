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
    aws-cli-key   packages/warren-server/images/warren-ecs-dev-base/aws-cli-team.asc
                  (the AWS CLI Team key that verifies the AWS CLI v2 zip's .sig)
                  vs the PGP PUBLIC KEY BLOCK in AWS's CLI install guide
                  (https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html,
                  which repeats it once per OS section; every copy must agree).
                  Compared after whitespace normalisation; on drift --write replaces
                  the file. ``gpg`` (throwaway GNUPGHOME) reads both keys' fingerprint
                  and expiry:
                    - fingerprint changed (rotation): also rewrites the fingerprint
                      asserted by the dev-base Dockerfile's ``grep -q`` line, and the
                      summary carries a ROTATED warning to check the new fingerprint
                      against AWS's docs by hand before merging;
                    - same fingerprint: reported as an expiry extension or another
                      metadata change (new signatures, user ids).
                  Warns when the resulting key expires within 60 days; once it has
                  actually expired, --expired-key-marker flags it so the weekly job
                  fails (see below). A page without
                  the block, or with conflicting blocks, fails this check (a warning in
                  the summary; the other checks still run). Without gpg on PATH the
                  check is reported as skipped.
    opencode      ``ARG OPENCODE_VERSION`` and ``ARG OPENCODE_SHA256_{AMD64,ARM64}`` in the
    codex         Dockerfiles (``ARG CODEX_*`` likewise) vs the latest stable GitHub release
                  of anomalyco/opencode (tag ``vX.Y.Z``) and openai/codex (``rust-vX.Y.Z``).
                  A bump rewrites the version and both sha256s, which come from the release
                  API's ``digest`` for each arch's tarball (opencode-linux-{x64,arm64},
                  codex-{x86_64,aarch64}-unknown-linux-musl); a release without them is
                  skipped. A codex bump also warns to redo warren's codex profile checks
                  (docs/harnesses.md: hook-trust hashes depend on codex's hook normalisation).
    pi            ``@earendil-works/pi-coding-agent`` in images/*/pi/package.json and
                  packages/warren-server/images/*/pi/package.json vs its npm ``latest``
                  dist-tag. --write rewrites package.json and regenerates package-lock.json
                  with ``npm install --package-lock-only --ignore-scripts`` in a Debian Node
                  container (node:<the ECS dev-base's NODE_VERSION>-bookworm-slim), so no npm
                  code runs on the host. Without docker the bump is reported as a warning
                  with the command to run by hand (``pi_lock_command``). It also warns when a
                  lockfile doesn't resolve the version its package.json pins.

Warnings also print as GitHub Actions ``::warning::`` annotations when GITHUB_ACTIONS=true.

Usage:
    scripts/bump_pins.py                 # report only, exit 0
    scripts/bump_pins.py --write         # rewrite the pins in place
    scripts/bump_pins.py --write --summary PATH --smoke-workflows PATH --expired-key-marker PATH

With --smoke-workflows, writes the file names of the smoke workflows whose
``paths:`` filter covers a changed image directory (one per line), so the
workflow can dispatch them against the bump branch.

With --expired-key-marker, creates that file (holding the reason) only when the AWS CLI key
the image would build with, i.e. upstream's after this run's changes, is already past its
expiry, and removes a stale one otherwise. The exit code stays 0 either way, so the workflow
can still push the PR and dispatch smoke tests before failing on the marker in its last step.
Near expiry and check failures are warnings only and never create the marker.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE_GLOBS = ("images/*/Dockerfile", "packages/warren-server/images/*/Dockerfile")
KNOWN_HOSTS = Path("packages/warren-server/images/ecs-base/ssh_known_hosts")
WORKFLOWS_DIR = Path(".github/workflows")
AWS_CLI_KEY = Path("packages/warren-server/images/warren-ecs-dev-base/aws-cli-team.asc")
AWS_CLI_DOCKERFILE = AWS_CLI_KEY.parent / "Dockerfile"
AWS_CLI_KEY_EXPIRY_WARN_DAYS = 60

NPM_DIST_TAGS_URL = "https://registry.npmjs.org/-/package/@anthropic-ai/claude-code/dist-tags"
CLAUDE_MANIFEST_URL = "https://downloads.claude.ai/claude-code-releases/{version}/manifest.json"
GITHUB_META_URL = "https://api.github.com/meta"
AWS_CLI_INSTALL_GUIDE_URL = "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"

_SEMVER = r"(\d+\.\d+\.\d+)"
CLAUDE_PIN_PATTERNS = (
    re.compile(r"(@anthropic-ai/claude-code@)" + _SEMVER),
    re.compile(r"(claude\.ai/install\.sh \| bash -s )" + _SEMVER),
    re.compile(r"(ARG CLAUDE_CODE_VERSION=)" + _SEMVER),
)
_SSH_KEY = re.compile(r"(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa) [A-Za-z0-9+/]+={0,2}")
_PGP_BLOCK = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----", re.S)
_DEFAULT_GPG = object()  # sentinel: look gpg up on PATH
_DEFAULT_LOCK = object()  # sentinel: regenerate pi's lockfile with docker if it's on PATH
_SHA256_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")

GITHUB_LATEST_RELEASE_URL = "https://api.github.com/repos/{repo}/releases/latest"


@dataclass(frozen=True)
class ReleaseBinary:
    """A harness installed from a GitHub release tarball, pinned by Dockerfile ARGs.

    ``ARG <arg>_VERSION=X.Y.Z`` plus ``ARG <arg>_SHA256_<ARCH>=<hex>`` for each key of
    ``assets`` (the release asset that arch downloads). Upstream is the repo's latest
    release (GitHub skips drafts and prereleases); its tag is ``tag_prefix`` + version and
    the new sha256s are the assets' ``digest`` fields from the release API.
    """
    kind: str
    repo: str
    tag_prefix: str
    arg: str
    assets: "tuple[tuple[str, str], ...]"  # (ARCH suffix, asset name)
    bump_warning: str = ""  # added to the summary's warnings when this pin is bumped


RELEASE_BINARIES = (
    ReleaseBinary("opencode", "anomalyco/opencode", "v", "OPENCODE",
                  (("AMD64", "opencode-linux-x64.tar.gz"), ("ARM64", "opencode-linux-arm64.tar.gz"))),
    ReleaseBinary("codex", "openai/codex", "rust-v", "CODEX",
                  (("AMD64", "codex-x86_64-unknown-linux-musl.tar.gz"),
                   ("ARM64", "codex-aarch64-unknown-linux-musl.tar.gz")),
                  bump_warning="codex {old} -> {new}: warren's codex profile (hook-trust hashes, "
                               "subcommands, config keys) was checked against {old}. Redo the codex "
                               "checks in docs/harnesses.md before merging; if codex changed how it "
                               "normalises hooks, warren's state hooks silently stop running."),
)

PI_PACKAGE = "@earendil-works/pi-coding-agent"  # was @mariozechner/pi-coding-agent (deprecated after 0.73.1)
PI_DIST_TAGS_URL = f"https://registry.npmjs.org/-/package/{PI_PACKAGE}/dist-tags"
PI_PACKAGE_GLOBS = ("images/*/pi/package.json", "packages/warren-server/images/*/pi/package.json")
# The Node the lockfile is regenerated with: the ECS dev-base's (nodejs.org's tarball on Debian).
PI_NODE_DOCKERFILE = Path("packages/warren-server/images/warren-ecs-dev-base/Dockerfile")
PI_LOCK_ARGS = ("npm", "install", "--package-lock-only", "--ignore-scripts", "--omit=dev",
                "--no-audit", "--no-fund")

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
    kind: str  # "claude-code" | "github-ssh" | "aws-cli-key" | "opencode" | "codex" | "pi"
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


def normalise_pgp_block(text: str) -> str:
    """Strip each line and the surrounding blank lines; one trailing newline."""
    return "\n".join(line.strip() for line in text.strip().splitlines()) + "\n"


def extract_pgp_blocks(page: str) -> list[str]:
    """Every public key block on an HTML page: tags stripped, entities decoded, normalised."""
    return [normalise_pgp_block(html.unescape(re.sub(r"<[^>]*>", "", m.group(0))))
            for m in _PGP_BLOCK.finditer(page)]


@dataclass
class KeyInfo:
    fingerprint: str
    expires: Optional[dt.date]  # None = never; earliest of the primary key and any signing subkey
    uids: "tuple[str, ...]"


class GpgError(Exception):
    pass


def gpg_key_info(gpg: str, armored: str) -> KeyInfo:
    """Read one public key with ``gpg --import-options show-only`` in a throwaway GNUPGHOME."""
    with tempfile.TemporaryDirectory(prefix="bump-pins-gpg-") as tmp:
        home = Path(tmp) / "gnupg"
        home.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(home), "HOME": tmp}
        try:
            out = subprocess.run(
                [gpg, "--batch", "--no-tty", "--with-colons", "--import-options", "show-only", "--import"],
                input=armored.encode(), capture_output=True, env=env, timeout=60, check=True,
            ).stdout.decode()
        except (OSError, subprocess.SubprocessError) as exc:
            raise GpgError(f"gpg could not read the key ({exc})") from exc
    rows = [line.split(":") for line in out.splitlines()]
    pubs = [r for r in rows if r[0] == "pub"]
    if len(pubs) != 1:
        raise GpgError(f"expected exactly one primary key, gpg found {len(pubs)}")
    fprs = [r[9] for r in rows if r[0] == "fpr" and len(r) > 9]
    if not fprs or not re.fullmatch(r"[0-9A-F]{40}", fprs[0]):
        raise GpgError("gpg printed no fingerprint for the primary key")
    # The primary key plus signing-capable subkeys (capabilities field has "s"): any may sign the zip.
    stamps = [int(r[6]) for r in rows
              if len(r) > 11 and r[6] and (r[0] == "pub" or (r[0] == "sub" and "s" in r[11]))]
    expires = dt.datetime.fromtimestamp(min(stamps), dt.timezone.utc).date() if stamps else None
    uids = tuple(r[9] for r in rows if r[0] == "uid" and len(r) > 9)
    return KeyInfo(fprs[0], expires, uids)


def spaced_fingerprint(fpr: str) -> str:
    """gpg --fingerprint's layout: ``FB5D B77F D5C1 18B8 0511  ADA8 A631 0ACC 4672 475C``."""
    groups = [fpr[i:i + 4] for i in range(0, len(fpr), 4)]
    return " ".join(groups[:5]) + "  " + " ".join(groups[5:])


def _describe(info: KeyInfo) -> str:
    return f"{info.fingerprint}, expires {info.expires or 'never'}"


def bump_aws_cli_key(root: Path, fetch: Fetcher, write: bool, gpg=_DEFAULT_GPG,
                     today: Optional[dt.date] = None) -> "tuple[list[Change], list[str], list[str], Optional[str]]":
    """Returns (changes, notes, warnings, expired); warnings go at the top of the summary.

    ``expired`` is set (to the reason) only when the key the image would build with is past
    its expiry; near expiry and failed/skipped checks leave it None.
    """
    key_path, docker_path = root / AWS_CLI_KEY, root / AWS_CLI_DOCKERFILE
    if not key_path.exists():
        return [], [f"aws-cli-key: {AWS_CLI_KEY} not found; skipped"], [], None

    def failed(why: str) -> "tuple[list[Change], list[str], list[str], Optional[str]]":
        return [], [], [f"aws-cli-key check FAILED: {why}. {AWS_CLI_KEY} was not checked; "
                         f"see {AWS_CLI_INSTALL_GUIDE_URL}"], None

    status, body = fetch(AWS_CLI_INSTALL_GUIDE_URL)
    if status != 200:
        return failed(f"GET {AWS_CLI_INSTALL_GUIDE_URL} returned {status}")
    blocks = extract_pgp_blocks(body.decode("utf-8", "replace"))
    if not blocks:
        return failed("no PGP PUBLIC KEY BLOCK found in the install guide (page layout changed?)")
    if len(set(blocks)) > 1:
        return failed(f"the install guide has {len(set(blocks))} different PGP public key blocks")
    upstream, current = blocks[0], normalise_pgp_block(key_path.read_text())
    same = upstream == current

    if gpg is _DEFAULT_GPG:
        gpg = shutil.which("gpg")
    if gpg is None:
        state = "matches" if same else "DIFFERS from"
        return [], [f"aws-cli-key: gpg not found; skipped (the install guide's key block {state} "
                    f"{AWS_CLI_KEY.name})"], [], None
    try:
        cur, up = gpg_key_info(gpg, current), gpg_key_info(gpg, upstream)
    except GpgError as exc:
        return failed(str(exc))

    changes: list[Change] = []
    notes: list[str] = []
    warnings: list[str] = []
    if same:
        notes.append(f"aws-cli-key: {AWS_CLI_KEY.name} matches the install guide ({_describe(cur)})")
    else:
        changes.append(Change("aws-cli-key", AWS_CLI_KEY, _describe(cur), _describe(up)))
        docker = docker_path.read_text() if docker_path.exists() else ""
        new_docker = docker
        if up.fingerprint != cur.fingerprint:
            warnings.append(
                "**AWS CLI signing key ROTATED: verify the new fingerprint against AWS's docs before merging.** "
                f"{cur.fingerprint} -> {up.fingerprint} ({', '.join(up.uids) or 'no user id'}). Compare it "
                f"with the \"Key fingerprint\" line of {AWS_CLI_INSTALL_GUIDE_URL} in a browser, not via this job.")
            old_spaced = spaced_fingerprint(cur.fingerprint)
            if old_spaced in docker:
                new_docker = docker.replace(old_spaced, spaced_fingerprint(up.fingerprint))
                changes.append(Change("aws-cli-key", AWS_CLI_DOCKERFILE,
                                      f"asserts {cur.fingerprint}", f"asserts {up.fingerprint}"))
            else:
                warnings.append(f"aws-cli-key: {AWS_CLI_DOCKERFILE} does not assert \"{old_spaced}\"; "
                                "update its fingerprint check by hand")
        elif up.expires != cur.expires:
            notes.append(f"aws-cli-key: same key, expiry {cur.expires or 'never'} -> {up.expires or 'never'} "
                         "(extension, no fingerprint change)")
        else:
            notes.append("aws-cli-key: same fingerprint and expiry, other key metadata changed "
                         "(signatures or user ids)")
        if write:
            key_path.write_text(upstream)
            if new_docker != docker:
                docker_path.write_text(new_docker)

    # Upstream's key is what the image builds with once this run's changes land.
    today = today or dt.date.today()
    expired: Optional[str] = None
    if up.expires is not None and (up.expires - today).days <= AWS_CLI_KEY_EXPIRY_WARN_DAYS:
        verb = "EXPIRED on" if up.expires < today else "expires on"
        warnings.append(f"AWS CLI signing key {up.fingerprint} {verb} {up.expires} and the install guide has "
                        "no newer key; warren-ecs-dev-base builds fail to verify the AWS CLI once it lapses")
        if up.expires < today:
            expired = f"AWS CLI signing key {up.fingerprint} expired on {up.expires} (checked {today})"
    return changes, notes, warnings, expired


def _version_arg(spec: ReleaseBinary) -> "re.Pattern[str]":
    return re.compile(rf"^(ARG {spec.arg}_VERSION=){_SEMVER}[ \t]*$", re.M)


def _sha_arg(spec: ReleaseBinary, arch: str) -> "re.Pattern[str]":
    return re.compile(rf"^(ARG {spec.arg}_SHA256_{arch}=)([0-9a-f]{{64}})[ \t]*$", re.M)


def find_release_pins(root: Path, spec: ReleaseBinary) -> list[Pin]:
    pins: list[Pin] = []
    for rel in dockerfiles(root):
        text = (root / rel).read_text()
        for m in _version_arg(spec).finditer(text):
            pins.append(Pin(rel, text.count("\n", 0, m.start()) + 1, m.group(2)))
    return pins


def latest_github_release(fetch: Fetcher, spec: ReleaseBinary) -> "tuple[Optional[tuple[str, dict[str, str]]], str]":
    """((version, {ARCH: sha256}), "") for the repo's latest release, or (None, why not)."""
    url = GITHUB_LATEST_RELEASE_URL.format(repo=spec.repo)
    status, body = fetch(url)
    if status != 200:
        return None, f"GET {url} returned {status}"
    try:
        release = json.loads(body)
    except ValueError:
        return None, f"GET {url} returned invalid JSON"
    tag = release.get("tag_name") or ""
    version = tag[len(spec.tag_prefix):] if tag.startswith(spec.tag_prefix) else ""
    if not re.fullmatch(_SEMVER, version) or release.get("draft") or release.get("prerelease"):
        return None, f"latest release {tag!r} is not a stable {spec.tag_prefix}X.Y.Z release"
    digests = {a.get("name"): a.get("digest") or "" for a in release.get("assets", [])}
    shas: dict[str, str] = {}
    for arch, asset in spec.assets:
        m = _SHA256_DIGEST.fullmatch(digests.get(asset, ""))
        if not m:
            return None, f"{tag} has no sha256 digest for {asset}"
        shas[arch] = m.group(1)
    return (version, shas), ""


def bump_release_binary(root: Path, fetch: Fetcher, spec: ReleaseBinary,
                        write: bool) -> "tuple[list[Change], list[str], list[str]]":
    """Returns (changes, notes, warnings). A bump rewrites the version and every sha256 ARG."""
    pins = find_release_pins(root, spec)
    if not pins:
        return [], [f"{spec.kind}: no pins found"], []
    latest, why = latest_github_release(fetch, spec)
    if latest is None:
        return [], [f"{spec.kind}: {why}; skipped"], []
    version, shas = latest
    stale = [p for p in pins if parse_version(p.version) < parse_version(version)]
    if not stale:
        return [], [f"{spec.kind}: all {len(pins)} pins at or above {version}"], []

    changes: list[Change] = []
    warnings: list[str] = []
    for rel in sorted({p.path for p in stale}):
        text = (root / rel).read_text()
        new_text = _version_arg(spec).sub(lambda m: m.group(1) + version, text)
        missing = []
        for arch, sha in shas.items():
            new_text, n = _sha_arg(spec, arch).subn(lambda m, sha=sha: m.group(1) + sha, new_text)
            if n != 1:
                missing.append(f"ARG {spec.arg}_SHA256_{arch}")
        if missing:
            warnings.append(f"{spec.kind}: {rel.as_posix()} pins {spec.arg}_VERSION but has no single "
                            f"{', '.join(missing)}; not bumped, update it by hand")
            continue
        if write:
            (root / rel).write_text(new_text)
        olds = sorted({p.version for p in stale if p.path == rel}, key=parse_version)
        changes.append(Change(spec.kind, rel, ", ".join(olds), version))
    if changes and spec.bump_warning:
        oldest = min((p.version for p in stale), key=parse_version)
        warnings.append(spec.bump_warning.format(old=oldest, new=version))
    return changes, [], warnings


# pi: the version is pinned in pi/package.json; the lockfile next to it pins the rest.
# A bump rewrites package.json and regenerates package-lock.json in a Debian Node container
# (the ECS dev-base's Node version), so nothing from npm runs on the host. By hand, from the
# repo root, for each pi/ dir (see pi_lock_command):
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/<image dir>/pi:/w" -w /w -e HOME=/tmp \
#     node:<NODE_VERSION>-bookworm-slim npm install --package-lock-only --ignore-scripts --omit=dev --no-audit --no-fund
LockRunner = Callable[[Path, Path], None]  # (repo root, pi dir relative to it); raises on failure


def find_pi_pins(root: Path) -> "tuple[list[Pin], list[str]]":
    pins: list[Pin] = []
    problems: list[str] = []
    found: set[Path] = set()
    for pattern in PI_PACKAGE_GLOBS:
        found.update(p.relative_to(root) for p in root.glob(pattern))
    for rel in sorted(found):
        try:
            version = json.loads((root / rel).read_text()).get("dependencies", {}).get(PI_PACKAGE, "")
        except ValueError:
            version = ""
        if re.fullmatch(_SEMVER, version):
            pins.append(Pin(rel, 0, version))
        else:
            problems.append(f"pi: {rel.as_posix()} doesn't pin {PI_PACKAGE} to an exact X.Y.Z")
    return pins, problems


def pi_lock_version(lock: Path) -> Optional[str]:
    """The pi version a package-lock.json resolves, or None if unreadable."""
    try:
        packages = json.loads(lock.read_text()).get("packages", {})
    except (OSError, ValueError):
        return None
    return packages.get(f"node_modules/{PI_PACKAGE}", {}).get("version")


def pi_node_image(root: Path) -> str:
    text = (root / PI_NODE_DOCKERFILE).read_text() if (root / PI_NODE_DOCKERFILE).exists() else ""
    m = re.search(rf"^ARG NODE_VERSION={_SEMVER}[ \t]*$", text, re.M)
    return f"node:{m.group(1)}-bookworm-slim" if m else "node:lts-bookworm-slim"


def pi_lock_command(root: Path, pi_dir: Path, mount: Optional[str] = None) -> list[str]:
    """docker run that regenerates pi_dir's package-lock.json (``mount`` overrides the host path)."""
    user = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else "0:0"
    return ["docker", "run", "--rm", "--user", user, "-v", f"{mount or (root / pi_dir).resolve()}:/w",
            "-w", "/w", "-e", "HOME=/tmp", pi_node_image(root), *PI_LOCK_ARGS]


def pi_manual_command(root: Path, pi_dir: Path) -> str:
    cmd = pi_lock_command(root, pi_dir, mount=f"$PWD/{pi_dir.as_posix()}")
    cmd[cmd.index("--user") + 1] = "$(id -u):$(id -g)"
    return " ".join(f'"{c}"' if "$" in c else c for c in cmd)


def docker_lock_runner(root: Path, pi_dir: Path) -> None:
    subprocess.run(pi_lock_command(root, pi_dir), check=True, timeout=900, capture_output=True)


def bump_pi(root: Path, fetch: Fetcher, write: bool,
            lock=_DEFAULT_LOCK) -> "tuple[list[Change], list[str], list[str]]":
    """Returns (changes, notes, warnings). ``lock`` regenerates a lockfile; None = can't."""
    pins, warnings = find_pi_pins(root)
    if not pins:
        return [], ["pi: no pins found"], warnings
    for p in pins:
        locked = pi_lock_version(root / p.path.parent / "package-lock.json")
        if locked != p.version:
            warnings.append(f"pi: {p.path.parent.as_posix()}/package-lock.json resolves {locked} but package.json "
                            f"pins {p.version}; regenerate it: {pi_manual_command(root, p.path.parent)}")
    status, body = fetch(PI_DIST_TAGS_URL)
    try:
        latest = json.loads(body).get("latest") if status == 200 else None
    except ValueError:
        latest = None
    if not latest or not re.fullmatch(_SEMVER, latest):
        return [], [f"pi: could not read the npm dist-tag 'latest' for {PI_PACKAGE}; skipped"], warnings
    stale = [p for p in pins if parse_version(p.version) < parse_version(latest)]
    if not stale:
        return [], [f"pi: all {len(pins)} pins at or above {latest}"], warnings
    if lock is _DEFAULT_LOCK:
        lock = docker_lock_runner if shutil.which("docker") else None

    changes: list[Change] = []
    notes: list[str] = []
    for p in stale:
        pkg, lockfile = root / p.path, root / p.path.parent / "package-lock.json"
        lock_rel = p.path.parent / "package-lock.json"
        if not write:
            changes.append(Change("pi", p.path, p.version, latest))
            continue
        if lock is None:
            warnings.append(f"pi {p.version} -> {latest} in {p.path.as_posix()}: not bumped, docker isn't available "
                            f"to regenerate the lockfile. Edit package.json, then run: "
                            f"{pi_manual_command(root, p.path.parent)}")
            continue
        old_pkg, old_lock = pkg.read_text(), lockfile.read_text() if lockfile.exists() else None
        pkg.write_text(re.sub(rf'("{re.escape(PI_PACKAGE)}"\s*:\s*")' + _SEMVER + '"',
                              lambda m: m.group(1) + latest + '"', old_pkg))
        try:
            lock(root, p.path.parent)
            got = pi_lock_version(lockfile)
            if got != latest:
                raise RuntimeError(f"the regenerated lockfile resolves {got}")
        except Exception as exc:  # noqa: BLE001 -- any failure restores the files and reports it
            pkg.write_text(old_pkg)
            if old_lock is not None:
                lockfile.write_text(old_lock)
            warnings.append(f"pi {p.version} -> {latest} in {p.path.as_posix()}: lockfile regeneration failed "
                            f"({exc}); not bumped. By hand: {pi_manual_command(root, p.path.parent)}")
            continue
        changes.append(Change("pi", p.path, p.version, latest))
        changes.append(Change("pi", lock_rel, f"resolves {p.version}", f"regenerated for {latest}"))
    return changes, notes, warnings


def smoke_workflows_for(root: Path, changed: list[Path]) -> list[str]:
    """Smoke workflows whose path filters cover a changed file's directory or any parent of it."""
    out: list[str] = []
    for wf in sorted((root / WORKFLOWS_DIR).glob("*-smoke.yml")):
        text = wf.read_text()
        if any(f"{d.as_posix()}/**" in text for c in changed for d in c.parents if d != Path(".")):
            out.append(wf.name)
    return out


def render_summary(changes: list[Change], notes: list[str], warnings: "list[str] | tuple[str, ...]" = ()) -> str:
    lines = ["Automated weekly pin check (AI6, `scripts/bump_pins.py`).", ""]
    if warnings:
        lines += [f"- :warning: {w}" for w in warnings]
        lines.append("")
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
        "bumped image by digest (warren-agent-base, warren-docker-ssh-base, warren-ecs-agent-base, warren-ecs-ssh-base) need a publish + digest "
        "bump afterwards.",
    ]
    return "\n".join(lines) + "\n"


def github_annotation(message: str) -> str:
    """A ``::warning::`` workflow command, with %, CR and LF escaped as GitHub documents."""
    escaped = message.replace("**", "").replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return f"::warning title=bump_pins::{escaped}"


def main(argv: Optional[list[str]] = None, fetch: Fetcher = http_fetch, root: Path = REPO_ROOT,
         gpg=_DEFAULT_GPG, today: Optional[dt.date] = None, lock=_DEFAULT_LOCK) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help="rewrite pins in place")
    ap.add_argument("--channel", default="stable", help="npm dist-tag for Claude Code (default: stable)")
    ap.add_argument("--summary", type=Path, help="write a markdown PR body here")
    ap.add_argument("--smoke-workflows", type=Path, help="write affected smoke workflow names here")
    ap.add_argument("--expired-key-marker", type=Path,
                    help="create this file only if the AWS CLI key the image would use has expired")
    args = ap.parse_args(argv)

    changes, notes = bump_claude(root, fetch, args.channel, args.write)
    ssh_changes, ssh_notes = bump_github_ssh(root, fetch, args.write)
    changes += ssh_changes
    notes += ssh_notes
    aws_changes, aws_notes, warnings, expired = bump_aws_cli_key(root, fetch, args.write, gpg=gpg, today=today)
    changes += aws_changes
    notes += aws_notes
    for spec in RELEASE_BINARIES:
        bin_changes, bin_notes, bin_warnings = bump_release_binary(root, fetch, spec, args.write)
        changes += bin_changes
        notes += bin_notes
        warnings += bin_warnings
    pi_changes, pi_notes, pi_warnings = bump_pi(root, fetch, args.write, lock=lock)
    changes += pi_changes
    notes += pi_notes
    warnings += pi_warnings

    summary = render_summary(changes, notes, warnings)
    print(summary)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for w in warnings:
            print(github_annotation(w))
    if args.summary:
        args.summary.write_text(summary)
    if args.smoke_workflows:
        wfs = smoke_workflows_for(root, [c.path for c in changes])
        args.smoke_workflows.write_text("".join(f"{w}\n" for w in wfs))
    if args.expired_key_marker:
        if expired:
            args.expired_key_marker.write_text(expired + "\n")
        else:
            args.expired_key_marker.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
