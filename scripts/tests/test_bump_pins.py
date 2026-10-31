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

        return bump_pins.bump_aws_cli_key(self.root, fetch, write, gpg=gpg, today=today)


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

    def test_repo_known_hosts_parses(self):
        keys = bump_pins.parse_known_hosts((bump_pins.REPO_ROOT / bump_pins.KNOWN_HOSTS).read_text())
        self.assertEqual({k.split()[0] for k in keys}, {"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"})


if __name__ == "__main__":
    unittest.main()
