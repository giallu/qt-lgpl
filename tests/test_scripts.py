"""Offline tests for scripts/check_upstream.py and scripts/apply_patches.py.

Run with:  python3 -m unittest discover -s tests -v
"""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import apply_patches  # noqa: E402
import check_upstream  # noqa: E402


def row(name, date, size="1.0K"):
    return (f'<tr><td valign="top">&nbsp;</td><td><a href="{name}">{name}</a></td>'
            f'<td align="right">{date}  </td><td align="right">{size}</td>'
            f'<td><a href="{name}.mirrorlist">Details</a></td></tr>\n')


def listing(*rows):
    return ('<html><body><table><tr><th><a href="?C=N;O=D">Name</a></th></tr>'
            '<tr><td><a href="/official_releases/qt/">Parent Directory</a></td></tr>\n'
            + "".join(rows) + "</table></body></html>").encode()


QTBASE_DIFF = b"""diff --git a/src/hello.txt b/src/hello.txt
--- a/src/hello.txt
+++ b/src/hello.txt
@@ -1 +1 @@
-hello
+hello, patched
"""
SHA = hashlib.sha256(QTBASE_DIFF).hexdigest()

CONFIG = {
    "lts_lines": ["6.12"],
    "submodules": ["qtbase", "qtsvg", "qt5compat"],
    "submodules_windows": [],
    "auto_build_new_versions": True,
}


class FakeSite:
    def __init__(self, pages):
        self.pages = pages
        self.requested = []

    def __call__(self, url):
        self.requested.append(url)
        return self.pages.get(url)


class CheckUpstreamTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        base = "https://download.qt.io"
        self.site = FakeSite({
            f"{base}/official_releases/qt/": listing(row("6.8/", "01-Jan-2026 10:00"),
                                                     row("6.12/", "30-Sep-2026 11:33")),
            f"{base}/official_releases/qt/6.12/": listing(
                row("6.12.0/", "30-Sep-2026 11:33"),
                row("6.12.1/", "20-Oct-2026 09:00"),
                row("CVE-2026-1-qtbase-6.12.diff", "15-Oct-2026 10:57"),
                row("CVE-2026-2-qtqt5compat-6.12-0001.diff", "14-Oct-2026 10:57"),
                row("CVE-2026-3-qtconnectivity-6.12.diff", "13-Oct-2026 10:57"),
                row("CVE-2026-4-qtsvg-6.12.zip", "12-Oct-2026 10:57"),
            ),
            f"{base}/official_releases/qt/6.12/CVE-2026-1-qtbase-6.12.diff": QTBASE_DIFF,
            f"{base}/official_releases/qt/6.12/CVE-2026-1-qtbase-6.12.diff.sha256":
                f"{SHA}  CVE-2026-1-qtbase-6.12.diff\n".encode(),
            f"{base}/official_releases/qt/6.12/CVE-2026-2-qtqt5compat-6.12-0001.diff": QTBASE_DIFF,
            f"{base}/official_releases/qt/6.12/CVE-2026-2-qtqt5compat-6.12-0001.diff.sha256":
                f"{SHA}\n".encode(),
        })
        check_upstream.fetch = self.site
        self.state = {"known_lines": None, "lines": {"6.12": {"versions": ["6.12.0"], "files": {}}}}

    def run_check(self):
        return check_upstream.check(CONFIG, self.state, self.tmp / "patches")

    def test_first_run(self):
        report = self.run_check()
        self.assertEqual([v["version"] for v in report["new_versions"]], ["6.12.1"])
        self.assertEqual(check_upstream.builds_to_dispatch(CONFIG, report), ["6.12.1"])
        # qtqt5compat is resolved to the qt5compat module directory
        self.assertEqual({p["module"] for p in report["new_patches"]}, {"qtbase", "qt5compat"})
        self.assertEqual([p["file"] for p in report["not_built"]], ["CVE-2026-3-qtconnectivity-6.12.diff"])
        self.assertEqual([p["file"] for p in report["manual_review"]], ["CVE-2026-4-qtsvg-6.12.zip"])
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["new_lines"], [])  # bootstrap: known_lines was null
        lock = json.loads((self.tmp / "patches/6.12/patches.json").read_text())
        # oldest upstream date first
        self.assertEqual([p["file"] for p in lock["patches"]],
                         ["CVE-2026-2-qtqt5compat-6.12-0001.diff", "CVE-2026-1-qtbase-6.12.diff"])
        self.assertEqual((self.tmp / "patches/6.12/CVE-2026-1-qtbase-6.12.diff").read_bytes(), QTBASE_DIFF)

    def test_second_run_is_quiet(self):
        self.run_check()
        self.site.requested.clear()
        report = self.run_check()
        self.assertFalse(any(report[k] for k in report), report)
        # unchanged patches are not downloaded again
        self.assertFalse([u for u in self.site.requested if u.endswith((".diff", ".sha256"))])

    def test_new_line_reported_after_bootstrap(self):
        self.run_check()
        self.site.pages["https://download.qt.io/official_releases/qt/"] += row("6.13/", "01-Nov-2026 10:00").encode()
        report = self.run_check()
        self.assertEqual(report["new_lines"], ["6.13"])

    def test_hash_mismatch_is_not_staged(self):
        url = "https://download.qt.io/official_releases/qt/6.12/CVE-2026-1-qtbase-6.12.diff"
        self.site.pages[url] = QTBASE_DIFF + b"tampered"
        report = self.run_check()
        self.assertTrue(any("mismatch" in e for e in report["errors"]))
        self.assertNotIn("CVE-2026-1-qtbase-6.12.diff", self.state["lines"]["6.12"]["files"])

    def test_changed_patch_detected(self):
        self.run_check()
        base = "https://download.qt.io/official_releases/qt/6.12/"
        new = QTBASE_DIFF.replace(b"patched", b"patched v2")
        self.site.pages[base + "CVE-2026-1-qtbase-6.12.diff"] = new
        self.site.pages[base + "CVE-2026-1-qtbase-6.12.diff.sha256"] = hashlib.sha256(new).hexdigest().encode()
        self.site.pages[base] = self.site.pages[base].replace(b"15-Oct-2026 10:57", b"22-Oct-2026 08:00")
        report = self.run_check()
        self.assertEqual([p["file"] for p in report["changed_patches"]], ["CVE-2026-1-qtbase-6.12.diff"])


class ApplyPatchesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.src = self.tmp / "qt-everywhere-src-6.12.0"
        (self.src / "qtbase/src").mkdir(parents=True)
        (self.src / "qtbase/src/hello.txt").write_text("hello\n")
        self.pdir = self.tmp / "patches/6.12"
        self.pdir.mkdir(parents=True)
        (self.pdir / "a.diff").write_bytes(QTBASE_DIFF)
        self.write_lock([{"file": "a.diff", "module": "qtbase", "cve": "CVE-1", "sha256": SHA}])

    def write_lock(self, patches):
        (self.pdir / "patches.json").write_text(json.dumps({"line": "6.12", "patches": patches}))

    def run_apply(self, modules="qtbase"):
        return apply_patches.main(["--src", str(self.src), "--line", "6.12", "--modules", modules,
                                   "--patches-dir", str(self.tmp / "patches"),
                                   "--report", str(self.tmp / "report.md")])

    def test_applies_then_detects_already_present(self):
        self.assertEqual(self.run_apply(), 0)
        self.assertEqual((self.src / "qtbase/src/hello.txt").read_text(), "hello, patched\n")
        self.assertIn("| applied |", (self.tmp / "report.md").read_text())
        self.assertEqual(self.run_apply(), 0)
        self.assertIn("already in this release", (self.tmp / "report.md").read_text())

    def test_hash_mismatch_fails(self):
        (self.pdir / "a.diff").write_bytes(QTBASE_DIFF + b"\n")
        self.assertEqual(self.run_apply(), 1)

    def test_unlisted_patch_fails(self):
        (self.pdir / "evil.diff").write_bytes(QTBASE_DIFF)
        self.assertEqual(self.run_apply(), 1)

    def test_module_not_built_is_skipped(self):
        self.assertEqual(self.run_apply(modules="qtsvg"), 0)
        self.assertEqual((self.src / "qtbase/src/hello.txt").read_text(), "hello\n")

    def test_conflicting_patch_fails(self):
        (self.src / "qtbase/src/hello.txt").write_text("something else\n")
        self.assertEqual(self.run_apply(), 1)

    def test_works_inside_a_git_checkout(self):
        # On CI the source tree sits inside the repository checkout.
        subprocess.run(["git", "init", "-q", str(self.tmp)], check=True)
        self.assertEqual(self.run_apply(), 0)
        self.assertEqual((self.src / "qtbase/src/hello.txt").read_text(), "hello, patched\n")


if __name__ == "__main__":
    unittest.main()
