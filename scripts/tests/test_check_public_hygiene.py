"""Tests for scripts/check_public_hygiene.py. Stdlib unittest.

Run: python3 -m unittest discover -s scripts/tests

Fixtures that would trip the scanner are assembled at runtime so this file
itself scans clean.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import check_public_hygiene as h  # noqa: E402

FAKE_ID = "4" * 3 + "5" * 3 + "6" * 3 + "7" * 3  # 12 digits, not a dummy id
DENY = frozenset({hashlib.sha256(b"sekritcorp").hexdigest(),
                  hashlib.sha256(b"inner-tool").hexdigest()})


def rules(line: str, deny: frozenset[str] = DENY) -> list[str]:
    return h.scan_line(line, deny)


class ScanLineTests(unittest.TestCase):
    def test_denylist_single_word_case_insensitive(self) -> None:
        self.assertEqual(rules("owned by SekritCorp"), ["denylist"])
        self.assertEqual(rules("sekritcorpish is a different word"), [])

    def test_denylist_two_word_token(self) -> None:
        self.assertEqual(rules("code/inner-tool"), ["denylist"])
        self.assertEqual(rules("mount inner_tool here"), ["denylist"])
        self.assertEqual(rules("org-inner-tool-dev"), ["denylist"])
        self.assertEqual(rules("inner tooling"), [])

    def test_account_id_in_arn(self) -> None:
        self.assertEqual(rules(f"arn:aws:iam::{FAKE_ID}:role/x"), ["aws-account-id"])
        self.assertEqual(rules(f"arn:aws-us-gov:sts::{FAKE_ID}:assumed-role/x"), ["aws-account-id"])

    def test_account_id_other_contexts(self) -> None:
        self.assertEqual(rules(f"{FAKE_ID}.dkr.ecr.us-east-1.amazonaws.com/x"), ["aws-account-id"])
        self.assertEqual(rules(f'"account_id": "{FAKE_ID}"'), ["aws-account-id"])
        self.assertEqual(rules(f"ACCOUNT_ID={FAKE_ID}"), ["aws-account-id"])

    def test_dummy_account_ids_allowed(self) -> None:
        self.assertEqual(rules("arn:aws:iam::123456789012:role/x"), [])
        self.assertEqual(rules("123456789012.dkr.ecr.eu-west-1.amazonaws.com"), [])

    def test_bare_12_digits_not_flagged(self) -> None:
        self.assertEqual(rules(f"timestamp {FAKE_ID}"), [])

    def test_sso_portal(self) -> None:
        self.assertEqual(rules("https://d-123.aws" + "apps.com/start/#/"), ["aws-sso-portal"])

    def test_sso_role_real_suffix_only(self) -> None:
        prefix = "AWSReserved" + "SSO_"
        self.assertEqual(rules(prefix + "AdministratorAccess_0123456789abcdef"), ["aws-sso-role"])
        self.assertEqual(rules(prefix + "MyPermissionSet_abc123def456"), [])

    def test_home_paths(self) -> None:
        self.assertEqual(rules("/Users/" + "jsmith/src/x"), ["home-path"])
        self.assertEqual(rules("cd /home/" + "jsmith"), ["home-path"])
        self.assertEqual(rules("/Users/me/.warren and /home/user and /home/runner/work"), [])
        self.assertEqual(rules("http://host/home/jsmith"), [])  # URL path, not absolute

    def test_gist_url(self) -> None:
        self.assertEqual(rules("https://gist.github.com/someone/" + "ab12" * 8), ["gist-url"])
        self.assertEqual(rules("https://gist.github.com/"), [])

    def test_scan_text_reports_line_numbers(self) -> None:
        found = h.scan_text("f.txt", "ok\nok\n/home/" + "jsmith\n", DENY)
        self.assertEqual([str(f) for f in found], ["f.txt:3: home-path"])


class DenylistFileTests(unittest.TestCase):
    def test_shipped_denylist_is_hashes_only(self) -> None:
        self.assertGreater(len(h.load_denylist()), 0)

    def test_rejects_plaintext_entry(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "deny.txt"
            p.write_text("# comment\nplaintext-token\n")
            with self.assertRaises(ValueError):
                h.load_denylist(p)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


class GitScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.name", "Test")
        _git(self.repo, "config", "user.email", "test@example.com")
        _git(self.repo, "config", "commit.gpgsign", "false")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _commit(self, name: str, text: str, msg: str) -> None:
        (self.repo / name).write_text(text)
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", msg)

    def test_tree_vs_history(self) -> None:
        self._commit("a.txt", "line one\nworks at SekritCorp\n", "add a")
        self._commit("a.txt", "line one\nworks at Example\n", "scrub inner-tool name")
        self.assertEqual(h.scan_tree(self.repo, DENY), [])
        hist = [str(f) for f in h.scan_history(self.repo, DENY)]
        self.assertEqual(len(hist), 2, hist)
        self.assertTrue(any(f.endswith(":a.txt:2: denylist") for f in hist), hist)
        self.assertTrue(any(":<message>:1: denylist" in f for f in hist), hist)

    def test_tree_finding(self) -> None:
        self._commit("b.md", "x\n/Users/" + "jsmith/y\n", "add b")
        self.assertEqual([str(f) for f in h.scan_tree(self.repo, DENY)], ["b.md:2: home-path"])


class RepoIsCleanTest(unittest.TestCase):
    def test_this_repo_tracked_files_are_clean(self) -> None:
        found = h.scan_tree(h.REPO_ROOT, h.load_denylist())
        self.assertEqual([str(f) for f in found], [])


if __name__ == "__main__":
    unittest.main()
