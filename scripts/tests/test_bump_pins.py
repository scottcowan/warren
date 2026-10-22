"""Tests for scripts/bump_pins.py (AI6). Stdlib unittest; no network.

Run: python3 -m unittest discover -s scripts/tests
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bump_pins  # noqa: E402

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
        self.write("packages/warren-server/images/ecs-base/Dockerfile", "FROM alpine\n")
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

    def test_repo_known_hosts_parses(self):
        keys = bump_pins.parse_known_hosts((bump_pins.REPO_ROOT / bump_pins.KNOWN_HOSTS).read_text())
        self.assertEqual({k.split()[0] for k in keys}, {"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"})


if __name__ == "__main__":
    unittest.main()
