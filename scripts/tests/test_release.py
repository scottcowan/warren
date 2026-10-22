"""Tests for scripts/release.py. Stdlib unittest; builds throwaway git repos.

Run: python3 -m unittest discover -s scripts/tests -p 'test_release.py'
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import release  # noqa: E402

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}

CONFIG = {
    "baseline": None,
    "components": {
        "server": {
            "version": "1.1.0",
            "paths": ["server/", "common/", "uv.lock"],
            "exclude": ["server/images/", "server/tests/"],
        },
        "base": {"version": "1.0.0", "paths": ["server/images/base/", "common/assets/"]},
        "dev": {"version": "2.3.4", "paths": ["images/dev/"]},
    },
}


class RepoTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, GIT_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git("init", "-q", "-b", "main")
        config = json.loads(json.dumps(CONFIG))
        self.baseline = self.commit("chore: initial", "README.md")
        config["baseline"] = self.baseline
        (self.root / ".github").mkdir()
        release.write_config(self.root, config)
        self.commit("chore: release config")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, capture_output=True, text=True, check=True).stdout.strip()

    def write(self, path, text="x\n"):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def commit(self, message, *paths):
        for path in paths:
            self.write(path, f"{message}\n")
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def pending(self):
        return {p.name: p for p in release.plan(self.root, release.load_config(self.root))}


class BumpTests(unittest.TestCase):
    def kind(self, subject, body=""):
        return release.bump_kind(release.Commit("0" * 40, subject, body, []))

    def test_feat_is_minor(self):
        self.assertEqual(self.kind("feat(cli): add thing"), release.MINOR)

    def test_bang_and_footer_are_major(self):
        self.assertEqual(self.kind("fix!: drop flag"), release.MAJOR)
        self.assertEqual(self.kind("feat(x)!: drop flag"), release.MAJOR)
        self.assertEqual(self.kind("fix: y", "BREAKING CHANGE: gone"), release.MAJOR)

    def test_anything_else_is_patch(self):
        for subject in ("fix: y", "build(deps): bump z", "doctor: raise floor", "Update README"):
            self.assertEqual(self.kind(subject), release.PATCH, subject)

    def test_next_version(self):
        self.assertEqual(release.next_version("1.2.3", release.PATCH), "1.2.4")
        self.assertEqual(release.next_version("1.2.3", release.MINOR), "1.3.0")
        self.assertEqual(release.next_version("1.2.3", release.MAJOR), "2.0.0")
        with self.assertRaises(release.ReleaseError):
            release.next_version("1.2", release.PATCH)


class PlanTests(RepoTest):
    def test_nothing_pending_without_input_changes(self):
        self.commit("docs: readme", "README.md", "docs/x.md")
        self.assertEqual(self.pending(), {})

    def test_shared_input_releases_every_consumer(self):
        self.commit("fix: banner", "common/assets/banner.sh")
        got = self.pending()
        self.assertEqual(set(got), {"server", "base"})
        self.assertEqual(got["server"].next, "1.1.1")
        self.assertEqual(got["base"].next, "1.0.1")

    def test_exact_file_and_exclude(self):
        self.commit("build(deps): bump lock", "uv.lock")
        self.commit("test: more", "server/tests/test_x.py")
        self.commit("fix: base image", "server/images/base/Dockerfile")
        got = self.pending()
        self.assertEqual([c.subject for c in got["server"].commits], ["build(deps): bump lock"])
        self.assertEqual([c.subject for c in got["base"].commits], ["fix: base image"])

    def test_largest_bump_wins(self):
        self.commit("fix: a", "images/dev/a")
        self.commit("feat: b", "images/dev/b")
        self.assertEqual(self.pending()["dev"].next, "2.4.0")

    def test_existing_tag_is_the_base(self):
        self.commit("fix: a", "images/dev/a")
        self.git("tag", "dev-v2.3.4")
        self.assertNotIn("dev", self.pending())
        self.commit("fix: b", "images/dev/b")
        self.assertEqual([c.subject for c in self.pending()["dev"].commits], ["fix: b"])

    def test_tag_outside_history_is_ignored(self):
        self.commit("fix: a", "images/dev/a")
        self.git("checkout", "-q", "--orphan", "other")
        self.git("commit", "-q", "--allow-empty", "-m", "unrelated")
        self.git("tag", "dev-v2.3.4")
        self.git("checkout", "-q", "main")
        self.assertEqual([c.subject for c in self.pending()["dev"].commits], ["fix: a"])


class PrepareTests(RepoTest):
    def test_prepare_bumps_versions_and_changelog(self):
        sha = self.commit("feat: thing", "server/app.py")
        pending = release.prepare(self.root, "2026-10-23")
        self.assertEqual([p.name for p in pending], ["server"])
        config = release.load_config(self.root)
        self.assertEqual(config["components"]["server"]["version"], "1.2.0")
        self.assertEqual(config["components"]["dev"]["version"], "2.3.4")
        changelog = (self.root / release.CHANGELOG).read_text()
        self.assertTrue(changelog.startswith(release.CHANGELOG_HEADER))
        self.assertIn(f"## server 1.2.0 (2026-10-23)\n\n- feat: thing ({sha[:7]})\n", changelog)
        self.assertEqual(release.pr_title(pending), "release: server 1.2.0")

    def test_newest_section_first(self):
        self.commit("fix: one", "images/dev/a")
        release.prepare(self.root, "2026-10-23")
        self.commit("release: dev 2.3.5")
        self.git("tag", "dev-v2.3.5")
        self.commit("fix: two", "images/dev/b")
        release.prepare(self.root, "2026-10-24")
        changelog = (self.root / release.CHANGELOG).read_text()
        self.assertLess(changelog.index("dev 2.3.6"), changelog.index("dev 2.3.5"))
        self.assertEqual(changelog.count(release.CHANGELOG_HEADER), 1)

    def test_prepare_is_noop_when_nothing_pending(self):
        self.assertEqual(release.prepare(self.root, "2026-10-23"), [])
        self.assertFalse((self.root / release.CHANGELOG).exists())


class ReleasedTests(RepoTest):
    def test_released_lists_changed_versions(self):
        before = self.git("rev-parse", "HEAD")
        self.commit("fix: a", "images/dev/a")
        release.prepare(self.root, "2026-10-23")
        self.commit("release: dev 2.3.5")
        self.assertEqual(release.released(self.root, before), {"dev": "dev-v2.3.5"})
        self.assertEqual(release.notes(self.root, "dev").splitlines()[0], "- fix: a (" + self.git("rev-parse", "--short=7", "HEAD~1") + ")")

    def test_released_is_empty_before_config_existed(self):
        self.assertEqual(release.released(self.root, self.baseline), {})

if __name__ == "__main__":
    unittest.main()
