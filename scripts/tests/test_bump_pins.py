"""Tests for scripts/bump_pins.py (AI6). Stdlib unittest; no network.

The aws-cli-key tests that read keys need gpg on PATH and are skipped without it (CI has it).
Their keys in fixtures/aws_cli_key/ are public blocks of throwaway test keys; the private
halves were never kept.

Run: python3 -m unittest discover -s scripts/tests
"""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bump_pins  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "aws_cli_key"
GPG = shutil.which("gpg")
needs_gpg = unittest.skipIf(GPG is None, "gpg not installed")
# Test keys in FIXTURES: A (expires 2036-01-01), A re-exported after extending it to
# 2037-01-01, and an unrelated key B (expires 2038-01-01).
KEY_A = (FIXTURES / "test-key-a.asc").read_text()
KEY_A_EXTENDED = (FIXTURES / "test-key-a-extended.asc").read_text()
KEY_B = (FIXTURES / "test-key-b.asc").read_text()
FPR_A = "4195AB9C359D378DCCAF8CC1B9A09BFBB6691DF9"
FPR_B = "8F467A94DF8A55B1B25D46328193BF917D1CA732"
INSTALL_GUIDE_A = (FIXTURES / "install-guide.html").read_text()  # carries KEY_A twice

ED = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
EC = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEez"
RSA_OLD = "ssh-rsa AAAAB3NzaOLD"
RSA_NEW = "ssh-rsa AAAAB3NzaNEW"


def make_fetch(dist_tags=None, manifests=(), meta_keys=None, npm_status=200, meta_status=200):
    def fetch(url):
        if url == bump_pins.NPM_DIST_TAGS_URL:
            return npm_status, json.dumps(dist_tags or {}).encode()
        if url == bump_pins.GITHUB_META_URL:
            return meta_status, json.dumps({"ssh_keys": meta_keys or []}).encode()
        for v in manifests:
            if url == bump_pins.CLAUDE_MANIFEST_URL.format(version=v):
                return 200, b"{}"
        return 404, b""

    return fetch


class RepoFixture(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.write("images/warren-base-claude-code/Dockerfile",
                   "FROM x\nRUN npm install -g @anthropic-ai/claude-code@2.1.301\n")
        self.write("images/warren-docker-dev-base/Dockerfile",
                   "FROM x\nRUN curl -fsSL https://claude.ai/install.sh | bash -s 2.1.301 \\\n    && true\n")
        self.write("packages/warren-server/images/warren-ecs-dev-base/Dockerfile",
                   "FROM x\nARG CLAUDE_CODE_VERSION=2.1.301\n"
                   "RUN curl -fsSL https://claude.ai/install.sh | bash -s ${CLAUDE_CODE_VERSION}\n")
        self.write("packages/warren-server/images/ecs-base/Dockerfile", "FROM debian\n")
        self.write("packages/warren-server/images/ecs-base/ssh_known_hosts",
                   f"github.com {ED}\ngithub.com {EC}\ngithub.com {RSA_OLD}\n")
        self.write(".github/workflows/warren-docker-dev-base-smoke.yml",
                   "on:\n  pull_request:\n    paths:\n      - images/warren-docker-dev-base/**\n")
        self.write(".github/workflows/warren-ecs-base-smoke.yml",
                   "on:\n  pull_request:\n    paths:\n      - packages/warren-server/images/ecs-base/**\n")
        self.write(".github/workflows/warren-cli-test.yml", "paths:\n  - images/warren-docker-dev-base/**\n")

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def read(self, rel):
        return (self.root / rel).read_text()


class TestClaude(RepoFixture):
    def test_finds_all_three_pin_forms(self):
        pins = bump_pins.find_claude_pins(self.root)
        self.assertEqual(len(pins), 3)
        self.assertEqual({p.version for p in pins}, {"2.1.301"})

    def test_bumps_every_form_when_newer_and_manifest_exists(self):
        fetch = make_fetch({"stable": "2.2.0", "latest": "2.3.0"}, manifests=["2.2.0"])
        changes, _ = bump_pins.bump_claude(self.root, fetch, "stable", write=True)
        self.assertEqual(len(changes), 3)
        self.assertIn("@anthropic-ai/claude-code@2.2.0", self.read("images/warren-base-claude-code/Dockerfile"))
        self.assertIn("bash -s 2.2.0 ", self.read("images/warren-docker-dev-base/Dockerfile"))
        ecs = self.read("packages/warren-server/images/warren-ecs-dev-base/Dockerfile")
        self.assertIn("ARG CLAUDE_CODE_VERSION=2.2.0", ecs)
        self.assertIn("bash -s ${CLAUDE_CODE_VERSION}", ecs)  # the ARG reference is untouched

    def test_report_only_does_not_write(self):
        fetch = make_fetch({"stable": "2.2.0"}, manifests=["2.2.0"])
        changes, _ = bump_pins.bump_claude(self.root, fetch, "stable", write=False)
        self.assertEqual(len(changes), 3)
        self.assertIn("2.1.301", self.read("images/warren-base-claude-code/Dockerfile"))

    def test_no_bump_when_up_to_date_or_older(self):
        for upstream in ("2.1.301", "2.1.300", "1.9.999"):
            fetch = make_fetch({"stable": upstream}, manifests=[upstream])
            changes, notes = bump_pins.bump_claude(self.root, fetch, "stable", write=True)
            self.assertEqual(changes, [], upstream)
            self.assertIn("at or above", notes[0])

    def test_semver_compare_not_lexical(self):
        fetch = make_fetch({"stable": "2.1.1000"}, manifests=["2.1.1000"])
        changes, _ = bump_pins.bump_claude(self.root, fetch, "stable", write=False)
        self.assertEqual(len(changes), 3)

    def test_skips_without_native_manifest(self):
        fetch = make_fetch({"stable": "2.2.0"}, manifests=[])
        changes, notes = bump_pins.bump_claude(self.root, fetch, "stable", write=True)
        self.assertEqual(changes, [])
        self.assertIn("no native release manifest", notes[0])
        self.assertIn("2.1.301", self.read("images/warren-base-claude-code/Dockerfile"))

    def test_registry_error_or_garbage_is_skipped(self):
        for fetch in (make_fetch(npm_status=503), make_fetch({"stable": "2.2.0; rm -rf /"})):
            changes, notes = bump_pins.bump_claude(self.root, fetch, "stable", write=True)
            self.assertEqual(changes, [])
            self.assertIn("skipped", notes[0])

    def test_channel_falls_back_to_latest(self):
        fetch = make_fetch({"latest": "2.2.0"}, manifests=["2.2.0"])
        changes, _ = bump_pins.bump_claude(self.root, fetch, "stable", write=False)
        self.assertEqual({c.new for c in changes}, {"2.2.0"})


class TestGithubSsh(RepoFixture):
    KH = "packages/warren-server/images/ecs-base/ssh_known_hosts"

    def test_match_in_any_order_is_no_change(self):
        fetch = make_fetch(meta_keys=[RSA_OLD, EC, ED])
        changes, notes = bump_pins.bump_github_ssh(self.root, fetch, write=True)
        self.assertEqual(changes, [])
        self.assertIn("match", notes[0])

    def test_rotation_rewrites_file(self):
        fetch = make_fetch(meta_keys=[ED, EC, RSA_NEW])
        changes, _ = bump_pins.bump_github_ssh(self.root, fetch, write=True)
        self.assertEqual(len(changes), 1)
        self.assertEqual(self.read(self.KH), f"github.com {ED}\ngithub.com {EC}\ngithub.com {RSA_NEW}\n")

    def test_rejects_malformed_upstream_key(self):
        before = self.read(self.KH)
        fetch = make_fetch(meta_keys=[ED, "ssh-rsa AAAA\ngithub.com ssh-rsa EVIL"])
        changes, notes = bump_pins.bump_github_ssh(self.root, fetch, write=True)
        self.assertEqual(changes, [])
        self.assertIn("malformed", notes[0])
        self.assertEqual(self.read(self.KH), before)

    def test_meta_failure_or_empty_never_empties_file(self):
        before = self.read(self.KH)
        for fetch in (make_fetch(meta_status=500), make_fetch(meta_keys=[])):
            changes, notes = bump_pins.bump_github_ssh(self.root, fetch, write=True)
            self.assertEqual(changes, [])
            self.assertIn("skipped", notes[0])
        self.assertEqual(self.read(self.KH), before)


def guide_with(key: str) -> bytes:
    """The fixture install guide with its key block(s) swapped for ``key``."""
    return INSTALL_GUIDE_A.replace(KEY_A.strip(), key.strip()).encode()


class AwsKeyFixture(RepoFixture):
    ASC = bump_pins.AWS_CLI_KEY.as_posix()
    DOCKERFILE = bump_pins.AWS_CLI_DOCKERFILE.as_posix()
    ASSERT_A = 'gpg --batch --fingerprint test-a@example.invalid | grep -q "4195 AB9C 359D 378D CCAF  8CC1 B9A0 9BFB B669 1DF9"'
    TODAY = dt.date(2030, 6, 1)

    def setUp(self):
        super().setUp()
        home = self.root / "home"  # gpg runs with GNUPGHOME/HOME under its own temp dir; belt and braces
        home.mkdir()
        patcher = mock.patch.dict(os.environ, {"HOME": str(home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.write(self.ASC, KEY_A)
        self.write(self.DOCKERFILE, self.read(self.DOCKERFILE) + f"RUN {self.ASSERT_A}\n")
        self.write(".github/workflows/warren-ecs-dev-base-smoke.yml",
                   "on:\n  pull_request:\n    paths:\n      - packages/warren-server/images/warren-ecs-dev-base/**\n")

    def run_check(self, page: "bytes | None", status=200, write=True, gpg=GPG, today=TODAY):
        def fetch(url):
            self.assertEqual(url, bump_pins.AWS_CLI_INSTALL_GUIDE_URL)
            return status, page or b""

        changes, notes, warnings, self.expired = bump_pins.bump_aws_cli_key(
            self.root, fetch, write, gpg=gpg, today=today)
        return changes, notes, warnings

    def run_main_with_marker(self, key: str, today: dt.date) -> "tuple[int, Path]":
        def fetch(url):
            return (200, guide_with(key)) if url == bump_pins.AWS_CLI_INSTALL_GUIDE_URL else (404, b"")

        marker = self.root / "expired-key"
        with contextlib.redirect_stdout(io.StringIO()):
            rc = bump_pins.main(["--write", "--expired-key-marker", str(marker)],
                                fetch=fetch, root=self.root, gpg=GPG, today=today)
        return rc, marker


class TestAwsCliKeyNoGpg(AwsKeyFixture):
    """Page parsing and failure paths; none of these reach gpg."""

    def test_extracts_and_normalises_every_block(self):
        page = "<pre><code>" + KEY_A.replace("\n", "  \r\n") + "</code></pre><p>x</p><code>" + KEY_A + "</code>"
        blocks = bump_pins.extract_pgp_blocks(page)
        self.assertEqual(blocks, [bump_pins.normalise_pgp_block(KEY_A)] * 2)

    def test_missing_key_block_fails_the_check_loudly(self):
        page = INSTALL_GUIDE_A.replace("BEGIN PGP PUBLIC KEY BLOCK", "BEGIN SOMETHING ELSE").encode()
        changes, notes, warnings = self.run_check(page)
        self.assertEqual((changes, notes), ([], []))
        self.assertIsNone(self.expired)  # a failed check is a warning, never a job failure
        self.assertIn("aws-cli-key check FAILED", warnings[0])
        self.assertIn("no PGP PUBLIC KEY BLOCK", warnings[0])
        self.assertEqual(self.read(self.ASC), KEY_A)

    def test_http_error_and_conflicting_blocks_fail(self):
        conflicting = INSTALL_GUIDE_A.replace(KEY_A.strip(), KEY_B.strip(), 1).encode()
        for page, status, why in ((b"", 503, "returned 503"), (conflicting, 200, "2 different")):
            changes, _, warnings = self.run_check(page, status=status)
            self.assertEqual(changes, [])
            self.assertIn(why, warnings[0])
        self.assertEqual(self.read(self.ASC), KEY_A)

    def test_gpg_missing_is_skipped_not_failed(self):
        for page, state in ((guide_with(KEY_A), "matches"), (guide_with(KEY_B), "DIFFERS from")):
            changes, notes, warnings = self.run_check(page, gpg=None)
            self.assertEqual((changes, warnings), ([], []))
            self.assertIn("gpg not found; skipped", notes[0])
            self.assertIn(state, notes[0])
        self.assertEqual(self.read(self.ASC), KEY_A)  # never written without gpg

    def test_failure_surfaces_in_summary_and_actions_annotation(self):
        def fetch(url):
            return 404, b""

        out = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), contextlib.redirect_stdout(out):
            bump_pins.main([], fetch=fetch, root=self.root, gpg=None)
        self.assertIn("- :warning: aws-cli-key check FAILED", out.getvalue())
        self.assertIn("::warning title=bump_pins::aws-cli-key check FAILED", out.getvalue())

    def test_fixtures_hold_no_private_key_material(self):
        for f in FIXTURES.iterdir():
            self.assertNotIn("PRIVATE", f.read_text(), f.name)

    def test_spaced_fingerprint_matches_gpg_layout(self):
        self.assertEqual(bump_pins.spaced_fingerprint("FB5DB77FD5C118B80511ADA8A6310ACC4672475C"),
                         "FB5D B77F D5C1 18B8 0511  ADA8 A631 0ACC 4672 475C")


@needs_gpg
class TestAwsCliKeyGpg(AwsKeyFixture):
    def test_gpg_reads_fingerprint_and_expiry(self):
        info = bump_pins.gpg_key_info(GPG, KEY_A)
        self.assertEqual((info.fingerprint, info.expires), (FPR_A, dt.date(2036, 1, 1)))
        self.assertEqual(info.uids, ("Warren Test Signing Key A <test-a@example.invalid>",))

    def test_unchanged_including_whitespace_only_differences(self):
        self.write(self.ASC, "\n" + KEY_A.replace("\n", "   \n"))
        before = self.read(self.ASC)
        changes, notes, warnings = self.run_check(guide_with(KEY_A))
        self.assertEqual((changes, warnings), ([], []))
        self.assertIn("matches the install guide", notes[0])
        self.assertIn(FPR_A, notes[0])
        self.assertEqual(self.read(self.ASC), before)

    def test_metadata_only_change_rewrites_key_not_dockerfile(self):
        dockerfile = self.read(self.DOCKERFILE)
        changes, notes, warnings = self.run_check(guide_with(KEY_A_EXTENDED))
        self.assertEqual(warnings, [])
        self.assertEqual([c.path.as_posix() for c in changes], [self.ASC])
        self.assertIn("expiry 2036-01-01 -> 2037-01-01", notes[0])
        self.assertIn("extension", notes[0])
        self.assertEqual(self.read(self.ASC), bump_pins.normalise_pgp_block(KEY_A_EXTENDED))
        self.assertEqual(self.read(self.DOCKERFILE), dockerfile)

    def test_rotated_fingerprint_rewrites_dockerfile_assertion(self):
        changes, _, warnings = self.run_check(guide_with(KEY_B))
        self.assertEqual({c.path.as_posix() for c in changes}, {self.ASC, self.DOCKERFILE})
        self.assertIn("AWS CLI signing key ROTATED: verify the new fingerprint against AWS's docs before merging",
                      warnings[0])
        self.assertIn(f"{FPR_A} -> {FPR_B}", warnings[0])
        self.assertEqual(self.read(self.ASC), bump_pins.normalise_pgp_block(KEY_B))
        dockerfile = self.read(self.DOCKERFILE)
        self.assertIn('grep -q "8F46 7A94 DF8A 55B1 B25D  4632 8193 BF91 7D1C A732"', dockerfile)
        self.assertNotIn("4195 AB9C", dockerfile)
        self.assertIn("ARG CLAUDE_CODE_VERSION=2.1.301", dockerfile)  # nothing else touched

    def test_rotation_report_only_does_not_write(self):
        dockerfile = self.read(self.DOCKERFILE)
        changes, _, warnings = self.run_check(guide_with(KEY_B), write=False)
        self.assertEqual(len(changes), 2)
        self.assertIn("ROTATED", warnings[0])
        self.assertEqual((self.read(self.ASC), self.read(self.DOCKERFILE)), (KEY_A, dockerfile))

    def test_rotation_without_assertion_in_dockerfile_warns(self):
        self.write(self.DOCKERFILE, "FROM x\n")
        changes, _, warnings = self.run_check(guide_with(KEY_B))
        self.assertEqual([c.path.as_posix() for c in changes], [self.ASC])
        self.assertIn("update its fingerprint check by hand", warnings[1])

    def test_near_expiry_warns_only_without_a_newer_upstream_key(self):
        near = dt.date(2035, 12, 1)  # KEY_A expires 2036-01-01, 31 days later
        _, _, warnings = self.run_check(guide_with(KEY_A), today=near)
        self.assertEqual(len(warnings), 1)
        self.assertIn(f"{FPR_A} expires on 2036-01-01", warnings[0])
        _, _, warnings = self.run_check(guide_with(KEY_A), today=dt.date(2036, 1, 2))
        self.assertIn("EXPIRED on 2036-01-01", warnings[0])
        _, _, warnings = self.run_check(guide_with(KEY_A), today=dt.date(2035, 10, 1))  # 92 days out
        self.assertEqual(warnings, [])
        _, notes, warnings = self.run_check(guide_with(KEY_A_EXTENDED), today=near)  # upstream extended it
        self.assertEqual(warnings, [])
        self.assertIn("extension", notes[0])

    def test_expired_key_is_flagged_and_writes_marker(self):
        self.run_check(guide_with(KEY_A), today=dt.date(2036, 1, 2))  # KEY_A expired 2036-01-01
        self.assertIn(f"{FPR_A} expired on 2036-01-01", self.expired)
        rc, marker = self.run_main_with_marker(KEY_A, dt.date(2036, 1, 2))
        self.assertEqual(rc, 0)  # the workflow fails on the marker, after the PR/smoke steps
        self.assertIn("expired on 2036-01-01", marker.read_text())

    def test_near_expiry_is_not_flagged(self):
        for today in (dt.date(2035, 12, 1), dt.date(2036, 1, 1)):  # 31 days out; the expiry day itself
            _, _, warnings = self.run_check(guide_with(KEY_A), today=today)
            self.assertEqual(len(warnings), 1, today)
            self.assertIsNone(self.expired, today)
        marker = self.root / "expired-key"
        marker.write_text("stale\n")  # a leftover marker is removed when the key is fine
        rc, marker = self.run_main_with_marker(KEY_A, dt.date(2035, 12, 1))
        self.assertEqual((rc, marker.exists()), (0, False))

    def test_normal_and_upstream_extended_keys_are_not_flagged(self):
        self.run_check(guide_with(KEY_A), today=self.TODAY)
        self.assertIsNone(self.expired)
        # The checked-in key has expired but upstream extended it: the refreshed key is fine.
        _, _, warnings = self.run_check(guide_with(KEY_A_EXTENDED), today=dt.date(2036, 1, 2), write=False)
        self.assertIsNone(self.expired)
        self.assertEqual(warnings, [])
        rc, marker = self.run_main_with_marker(KEY_A, self.TODAY)
        self.assertEqual((rc, marker.exists()), (0, False))

    def test_near_expiry_emits_actions_warning(self):
        def fetch(url):
            return (200, guide_with(KEY_A)) if url == bump_pins.AWS_CLI_INSTALL_GUIDE_URL else (404, b"")

        out = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), contextlib.redirect_stdout(out):
            bump_pins.main([], fetch=fetch, root=self.root, gpg=GPG, today=dt.date(2035, 12, 1))
        self.assertIn("::warning title=bump_pins::AWS CLI signing key", out.getvalue())
        out = io.StringIO()
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": ""}), contextlib.redirect_stdout(out):
            bump_pins.main([], fetch=fetch, root=self.root, gpg=GPG, today=dt.date(2035, 12, 1))
        self.assertNotIn("::warning", out.getvalue())

    def test_key_change_dispatches_dev_base_smoke(self):
        def fetch(url):
            return (200, guide_with(KEY_B)) if url == bump_pins.AWS_CLI_INSTALL_GUIDE_URL else (404, b"")

        summary, smoke = self.root / "summary.md", self.root / "smoke.txt"
        with contextlib.redirect_stdout(io.StringIO()):
            bump_pins.main(["--write", "--summary", str(summary), "--smoke-workflows", str(smoke)],
                           fetch=fetch, root=self.root, gpg=GPG, today=self.TODAY)
        self.assertEqual(smoke.read_text().split(), ["warren-ecs-dev-base-smoke.yml"])
        body = summary.read_text()
        self.assertIn("| aws-cli-key | `packages/warren-server/images/warren-ecs-dev-base/aws-cli-team.asc` |", body)
        self.assertIn("ROTATED", body)


SHA = {c: c * 64 for c in "abcdef"}
OPENCODE = bump_pins.RELEASE_BINARIES[0]
CODEX = bump_pins.RELEASE_BINARIES[1]


def release_fetch(releases, base=None):
    """fetch() serving {repo: release JSON} at the latest-release URL; else ``base`` or 404."""
    def fetch(url):
        for repo, body in releases.items():
            if url == bump_pins.GITHUB_LATEST_RELEASE_URL.format(repo=repo):
                return (200, json.dumps(body).encode()) if body is not None else (503, b"")
        return base(url) if base else (404, b"")
    return fetch


def release(tag, digests, prerelease=False):
    return {"tag_name": tag, "draft": False, "prerelease": prerelease,
            "assets": [{"name": n, "digest": d} for n, d in digests.items()]}


def codex_release(tag="rust-v0.170.0", amd=SHA["c"], arm=SHA["d"]):
    return release(tag, {"codex-x86_64-unknown-linux-musl.tar.gz": f"sha256:{amd}",
                         "codex-aarch64-unknown-linux-musl.tar.gz": f"sha256:{arm}",
                         "codex-x86_64-unknown-linux-musl.zst": f"sha256:{SHA['f']}"})


def codex_args(version="0.166.0", amd=SHA["a"], arm=SHA["b"]):
    return (f"ARG CODEX_VERSION={version}\nARG CODEX_SHA256_AMD64={amd}\nARG CODEX_SHA256_ARM64={arm}\n"
            'RUN curl ".../rust-v${CODEX_VERSION}/codex.tar.gz"\n')


class ReleaseFixture(RepoFixture):
    DOCKER = "images/warren-docker-dev-base/Dockerfile"
    ECS = "packages/warren-server/images/warren-ecs-dev-base/Dockerfile"

    def setUp(self):
        super().setUp()
        self.write(self.DOCKER, "FROM x\nARG OPENCODE_VERSION=1.19.5\n"
                   f"ARG OPENCODE_SHA256_AMD64={SHA['a']}\nARG OPENCODE_SHA256_ARM64={SHA['b']}\n" + codex_args())
        self.write(self.ECS, "FROM x\nARG CLAUDE_CODE_VERSION=2.1.301\nARG NODE_VERSION=24.22.2\n" + codex_args())


class TestReleaseBinary(ReleaseFixture):
    def test_finds_pins_per_harness(self):
        self.assertEqual([p.path.as_posix() for p in bump_pins.find_release_pins(self.root, OPENCODE)], [self.DOCKER])
        self.assertEqual(sorted(p.path.as_posix() for p in bump_pins.find_release_pins(self.root, CODEX)),
                         sorted([self.DOCKER, self.ECS]))

    def test_bump_rewrites_version_and_both_checksums(self):
        fetch = release_fetch({"openai/codex": codex_release()})
        changes, _, warnings = bump_pins.bump_release_binary(self.root, fetch, CODEX, write=True)
        self.assertEqual(sorted(c.path.as_posix() for c in changes), sorted([self.DOCKER, self.ECS]))
        self.assertEqual({(c.old, c.new) for c in changes}, {("0.166.0", "0.170.0")})
        for rel in (self.DOCKER, self.ECS):
            text = self.read(rel)
            self.assertIn("ARG CODEX_VERSION=0.170.0\n", text)
            self.assertIn(f"ARG CODEX_SHA256_AMD64={SHA['c']}\n", text)
            self.assertIn(f"ARG CODEX_SHA256_ARM64={SHA['d']}\n", text)
            self.assertIn("rust-v${CODEX_VERSION}", text)  # the ARG reference is untouched
        self.assertIn(f"ARG OPENCODE_SHA256_AMD64={SHA['a']}\n", self.read(self.DOCKER))  # other harness untouched
        self.assertEqual(len(warnings), 1)
        self.assertIn("codex 0.166.0 -> 0.170.0", warnings[0])
        self.assertIn("docs/harnesses.md", warnings[0])

    def test_opencode_bump_has_no_extra_warning(self):
        fetch = release_fetch({"anomalyco/opencode": release("v1.20.0", {
            "opencode-linux-x64.tar.gz": f"sha256:{SHA['e']}", "opencode-linux-arm64.tar.gz": f"sha256:{SHA['f']}"})})
        changes, _, warnings = bump_pins.bump_release_binary(self.root, fetch, OPENCODE, write=True)
        self.assertEqual([(c.kind, c.path.as_posix(), c.new) for c in changes], [("opencode", self.DOCKER, "1.20.0")])
        self.assertEqual(warnings, [])
        text = self.read(self.DOCKER)
        self.assertIn("ARG OPENCODE_VERSION=1.20.0\n", text)
        self.assertIn(f"ARG OPENCODE_SHA256_AMD64={SHA['e']}\nARG OPENCODE_SHA256_ARM64={SHA['f']}\n", text)

    def test_report_only_does_not_write(self):
        before = self.read(self.ECS)
        changes, _, _ = bump_pins.bump_release_binary(self.root, release_fetch({"openai/codex": codex_release()}),
                                                     CODEX, write=False)
        self.assertEqual(len(changes), 2)
        self.assertEqual(self.read(self.ECS), before)

    def test_up_to_date_or_older_is_no_change(self):
        for tag in ("rust-v0.166.0", "rust-v0.99.9"):
            changes, notes, _ = bump_pins.bump_release_binary(
                self.root, release_fetch({"openai/codex": codex_release(tag)}), CODEX, write=True)
            self.assertEqual(changes, [], tag)
            self.assertIn("at or above", notes[0])

    def test_unusable_release_is_skipped_without_writing(self):
        before = self.read(self.ECS)
        cases = {
            "http error": None,
            "prerelease": {**codex_release(), "prerelease": True},
            "odd tag": codex_release(tag="v0.170.0"),
            "alpha tag": codex_release(tag="rust-v0.170.0-alpha.1"),
            "missing digest": release("rust-v0.170.0", {"codex-x86_64-unknown-linux-musl.tar.gz": f"sha256:{SHA['c']}"}),
            "bad digest": codex_release(amd="not-hex"),
        }
        for name, body in cases.items():
            changes, notes, _ = bump_pins.bump_release_binary(
                self.root, release_fetch({"openai/codex": body}), CODEX, write=True)
            self.assertEqual(changes, [], name)
            self.assertIn("skipped", notes[0], name)
        self.assertEqual(self.read(self.ECS), before)

    def test_file_without_checksum_args_is_not_bumped(self):
        self.write(self.ECS, "FROM x\nARG CODEX_VERSION=0.166.0\n")
        changes, _, warnings = bump_pins.bump_release_binary(
            self.root, release_fetch({"openai/codex": codex_release()}), CODEX, write=True)
        self.assertEqual([c.path.as_posix() for c in changes], [self.DOCKER])
        self.assertIn("ARG CODEX_VERSION=0.166.0", self.read(self.ECS))
        self.assertTrue(any("by hand" in w and self.ECS in w for w in warnings))


PI_PKG = "images/warren-docker-dev-base/pi/package.json"
PI_PKG_ECS = "packages/warren-server/images/warren-ecs-dev-base/pi/package.json"


def pi_package(version):
    return json.dumps({"name": "warren-pi", "private": True, "dependencies": {bump_pins.PI_PACKAGE: version}},
                      indent=2) + "\n"


def pi_lock(version):
    return json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {bump_pins.PI_PACKAGE: version}},
        f"node_modules/{bump_pins.PI_PACKAGE}": {"version": version}}}, indent=2) + "\n"


def pi_fetch(latest, status=200):
    def fetch(url):
        if url == bump_pins.PI_DIST_TAGS_URL:
            return status, json.dumps({"latest": latest}).encode()
        return 404, b""
    return fetch


class TestPi(ReleaseFixture):
    def setUp(self):
        super().setUp()
        for pkg in (PI_PKG, PI_PKG_ECS):
            self.write(pkg, pi_package("1.5.0"))
            self.write(pkg.replace("package.json", "package-lock.json"), pi_lock("1.5.0"))
        self.calls = []

    def fake_lock(self, root, pi_dir):
        """Stands in for the docker run: resolves whatever package.json now pins."""
        self.calls.append(pi_dir.as_posix())
        version = json.loads((root / pi_dir / "package.json").read_text())["dependencies"][bump_pins.PI_PACKAGE]
        (root / pi_dir / "package-lock.json").write_text(pi_lock(version))

    def test_bump_rewrites_package_json_and_regenerates_each_lockfile(self):
        changes, _, warnings = bump_pins.bump_pi(self.root, pi_fetch("1.6.0"), write=True, lock=self.fake_lock)
        self.assertEqual(warnings, [])
        self.assertEqual(sorted(self.calls), sorted(str(Path(p).parent.as_posix()) for p in (PI_PKG, PI_PKG_ECS)))
        for pkg in (PI_PKG, PI_PKG_ECS):
            self.assertEqual(json.loads(self.read(pkg))["dependencies"][bump_pins.PI_PACKAGE], "1.6.0")
            self.assertEqual(bump_pins.pi_lock_version(self.root / pkg.replace("package.json", "package-lock.json")),
                             "1.6.0")
        self.assertEqual({c.path.name for c in changes}, {"package.json", "package-lock.json"})
        self.assertEqual(len(changes), 4)

    def test_report_only_lists_the_bump_without_running_npm(self):
        changes, _, _ = bump_pins.bump_pi(self.root, pi_fetch("1.6.0"), write=False, lock=self.fake_lock)
        self.assertEqual(self.calls, [])
        self.assertEqual(sorted(c.path.as_posix() for c in changes), sorted([PI_PKG, PI_PKG_ECS]))
        self.assertIn("1.5.0", self.read(PI_PKG))

    def test_without_docker_reports_drift_and_the_manual_command(self):
        changes, _, warnings = bump_pins.bump_pi(self.root, pi_fetch("1.6.0"), write=True, lock=None)
        self.assertEqual(changes, [])
        self.assertEqual(len(warnings), 2)
        self.assertIn("docker run", warnings[0])
        self.assertIn("npm install --package-lock-only --ignore-scripts", warnings[0])
        self.assertIn("node:24.22.2-bookworm-slim", warnings[0])  # the ECS dev-base's Node
        self.assertIn("1.5.0", self.read(PI_PKG))

    def test_failed_regeneration_restores_both_files(self):
        def broken(root, pi_dir):
            (root / pi_dir / "package-lock.json").write_text("garbage")
            raise subprocess.CalledProcessError(1, ["docker"])
        before = {p: self.read(p) for p in (PI_PKG, PI_PKG.replace("package.json", "package-lock.json"))}
        changes, _, warnings = bump_pins.bump_pi(self.root, pi_fetch("1.6.0"), write=True, lock=broken)
        self.assertEqual(changes, [])
        self.assertTrue(all("regeneration failed" in w for w in warnings))
        self.assertEqual({p: self.read(p) for p in before}, before)

    def test_lockfile_resolving_the_wrong_version_is_rejected(self):
        def stale(root, pi_dir):
            (root / pi_dir / "package-lock.json").write_text(pi_lock("1.5.0"))
        changes, _, warnings = bump_pins.bump_pi(self.root, pi_fetch("1.6.0"), write=True, lock=stale)
        self.assertEqual(changes, [])
        self.assertIn("resolves 1.5.0", warnings[0])
        self.assertIn("1.5.0", self.read(PI_PKG))

    def test_up_to_date_and_registry_errors_are_no_change(self):
        for fetch in (pi_fetch("1.5.0"), pi_fetch("1.4.9"), pi_fetch("1.6.0", status=500), pi_fetch("latest")):
            changes, notes, _ = bump_pins.bump_pi(self.root, fetch, write=True, lock=self.fake_lock)
            self.assertEqual(changes, [])
            self.assertTrue(notes)
        self.assertEqual(self.calls, [])

    def test_out_of_sync_lockfile_warns(self):
        self.write(PI_PKG.replace("package.json", "package-lock.json"), pi_lock("1.4.0"))
        _, _, warnings = bump_pins.bump_pi(self.root, pi_fetch("1.5.0"), write=True, lock=self.fake_lock)
        self.assertEqual(len(warnings), 1)
        self.assertIn("resolves 1.4.0", warnings[0])

    def test_range_pin_is_reported(self):
        self.write(PI_PKG, pi_package("^1.5.0"))
        pins, problems = bump_pins.find_pi_pins(self.root)
        self.assertEqual([p.path.as_posix() for p in pins], [PI_PKG_ECS])
        self.assertIn("exact X.Y.Z", problems[0])

    def test_lock_command_runs_npm_only_in_a_container(self):
        cmd = bump_pins.pi_lock_command(self.root, Path(PI_PKG).parent)
        self.assertEqual(cmd[:3], ["docker", "run", "--rm"])
        self.assertIn("node:24.22.2-bookworm-slim", cmd)
        self.assertEqual(cmd[cmd.index("-e") + 1], "HOME=/tmp")
        self.assertIn("--ignore-scripts", cmd)

    def test_pi_bump_dispatches_the_dev_base_smoke(self):
        self.write(".github/workflows/warren-ecs-dev-base-smoke.yml",
                   "on:\n  pull_request:\n    paths:\n      - packages/warren-server/images/warren-ecs-dev-base/**\n")
        changed = [Path(PI_PKG_ECS), Path(PI_PKG_ECS.replace("package.json", "package-lock.json"))]
        self.assertEqual(bump_pins.smoke_workflows_for(self.root, changed), ["warren-ecs-dev-base-smoke.yml"])

    def test_main_reports_every_harness(self):
        fetch = release_fetch({"openai/codex": codex_release(), "anomalyco/opencode": None},
                              base=lambda url: pi_fetch("1.6.0")(url))
        summary, smoke = self.root / "summary.md", self.root / "smoke.txt"
        with contextlib.redirect_stdout(io.StringIO()):
            bump_pins.main(["--write", "--summary", str(summary), "--smoke-workflows", str(smoke)],
                           fetch=fetch, root=self.root, gpg=None, lock=self.fake_lock)
        body = summary.read_text()
        self.assertIn(f"| codex | `{self.ECS}` | 0.166.0 | 0.170.0 |", body)
        self.assertIn(f"| pi | `{PI_PKG}` | 1.5.0 | 1.6.0 |", body)
        self.assertIn("opencode: GET https://api.github.com/repos/anomalyco/opencode/releases/latest returned 503", body)
        self.assertIn("Redo the codex checks", body)
        self.assertEqual(smoke.read_text().split(), ["warren-docker-dev-base-smoke.yml"])


class TestMain(RepoFixture):
    def test_end_to_end_outputs(self):
        fetch = make_fetch({"stable": "2.2.0"}, manifests=["2.2.0"], meta_keys=[ED, EC, RSA_NEW])
        summary = self.root / "summary.md"
        smoke = self.root / "smoke.txt"
        rc = bump_pins.main(["--write", "--summary", str(summary), "--smoke-workflows", str(smoke)],
                            fetch=fetch, root=self.root)
        self.assertEqual(rc, 0)
        body = summary.read_text()
        self.assertIn("| claude-code |", body)
        self.assertIn("GitHub SSH host keys changed", body)
        # only *-smoke.yml workflows, and only those covering a changed directory
        self.assertEqual(smoke.read_text().split(),
                         ["warren-docker-dev-base-smoke.yml", "warren-ecs-base-smoke.yml"])

    def test_no_changes_writes_empty_smoke_list(self):
        fetch = make_fetch({"stable": "2.1.301"}, manifests=["2.1.301"], meta_keys=[ED, EC, RSA_OLD])
        smoke = self.root / "smoke.txt"
        bump_pins.main(["--write", "--smoke-workflows", str(smoke)], fetch=fetch, root=self.root)
        self.assertEqual(smoke.read_text(), "")


class TestRealRepo(unittest.TestCase):
    """The patterns must keep matching the repo's actual Dockerfiles."""

    def test_repo_has_claude_pins_in_each_image(self):
        paths = {p.path.as_posix() for p in bump_pins.find_claude_pins(bump_pins.REPO_ROOT)}
        self.assertIn("images/warren-base-claude-code/Dockerfile", paths)
        self.assertIn("images/warren-docker-dev-base/Dockerfile", paths)
        self.assertIn("packages/warren-server/images/warren-ecs-dev-base/Dockerfile", paths)

    @needs_gpg
    def test_repo_dockerfile_asserts_the_checked_in_aws_key_once(self):
        info = bump_pins.gpg_key_info(GPG, (bump_pins.REPO_ROOT / bump_pins.AWS_CLI_KEY).read_text())
        dockerfile = (bump_pins.REPO_ROOT / bump_pins.AWS_CLI_DOCKERFILE).read_text()
        # A rotation rewrites only the spaced form on the grep line, so no other copy may exist.
        self.assertEqual(dockerfile.count(bump_pins.spaced_fingerprint(info.fingerprint)), 1)
        self.assertNotIn(info.fingerprint, dockerfile)

    def test_repo_harness_pins_match_the_images(self):
        # opencode is only in the Docker-env dev-base; codex and pi are in both dev-bases.
        def paths(spec):
            return sorted(p.path.as_posix() for p in bump_pins.find_release_pins(bump_pins.REPO_ROOT, spec))
        self.assertEqual(paths(OPENCODE), ["images/warren-docker-dev-base/Dockerfile"])
        self.assertEqual(paths(CODEX), ["images/warren-docker-dev-base/Dockerfile",
                                        "packages/warren-server/images/warren-ecs-dev-base/Dockerfile"])
        pins, problems = bump_pins.find_pi_pins(bump_pins.REPO_ROOT)
        self.assertEqual(problems, [])
        self.assertEqual(sorted(p.path.as_posix() for p in pins), [PI_PKG, PI_PKG_ECS])
        for spec in bump_pins.RELEASE_BINARIES:
            for rel in paths(spec):
                text = (bump_pins.REPO_ROOT / rel).read_text()
                for arch, _ in spec.assets:
                    self.assertEqual(len(bump_pins._sha_arg(spec, arch).findall(text)), 1, (rel, arch))

    def test_repo_pi_lockfiles_match_their_package_json_and_each_other(self):
        pins, _ = bump_pins.find_pi_pins(bump_pins.REPO_ROOT)
        locks = set()
        for p in pins:
            lock = bump_pins.REPO_ROOT / p.path.parent / "package-lock.json"
            self.assertEqual(bump_pins.pi_lock_version(lock), p.version)
            locks.add(lock.read_text())
        self.assertEqual(len(locks), 1)

    def test_repo_known_hosts_parses(self):
        keys = bump_pins.parse_known_hosts((bump_pins.REPO_ROOT / bump_pins.KNOWN_HOSTS).read_text())
        self.assertEqual({k.split()[0] for k in keys}, {"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"})

    def test_dev_base_bump_dispatches_the_ssh_base_smoke_too(self):
        # warren-ecs-ssh-base builds FROM dev-base, so a dev-base pin bump is smoke-tested there too.
        changed = [Path("packages/warren-server/images/warren-ecs-dev-base/Dockerfile")]
        smoke = bump_pins.smoke_workflows_for(bump_pins.REPO_ROOT, changed)
        self.assertIn("warren-ecs-dev-base-smoke.yml", smoke)
        self.assertIn("warren-ecs-ssh-base-smoke.yml", smoke)


if __name__ == "__main__":
    unittest.main()
