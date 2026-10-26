"""Offline tests for scripts/check_upstream.py and scripts/apply_patches.py.

Run with:  python3 -m unittest discover -s tests -v
"""

import datetime as dt
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
import make_sbom_extras  # noqa: E402
import compare_patch_sets  # noqa: E402


def row(name, date, size="1.0K"):
    return (f'<tr><td valign="top">&nbsp;</td><td><a href="{name}">{name}</a></td>'
            f'<td align="right">{date}  </td><td align="right">{size}</td>'
            f'<td><a href="{name}.mirrorlist">Details</a></td></tr>\n')


def listing(*rows):
    return ('<html><body><table><tr><th><a href="?C=N;O=D">Name</a></th></tr>'
            '<tr><td><a href="/official_releases/qt/">Parent Directory</a></td></tr>\n'
            + "".join(rows) + "</table></body></html>").encode()


import io
import zipfile


def make_zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


QTBASE_DIFF = b"""diff --git a/src/hello.txt b/src/hello.txt
--- a/src/hello.txt
+++ b/src/hello.txt
@@ -1 +1 @@
-hello
+hello, patched
"""
SHA = hashlib.sha256(QTBASE_DIFF).hexdigest()
ZIP = make_zip([("CVE-2026-4-qtsvg-6.12-0002.diff", b"two"), ("CVE-2026-4-qtsvg-6.12-0001.diff", b"one"),
                ("__MACOSX/._CVE-2026-4-qtsvg-6.12-0001.diff", b"junk")])

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
                row("CVE-2026-4-qtsvg-6.12-0001.diff", "01-Oct-2026 10:57"),
                row("CVE-2026-4-qtsvg-6.12.zip", "12-Oct-2026 10:57"),
            ),
            f"{base}/official_releases/qt/6.12/CVE-2026-4-qtsvg-6.12.zip": ZIP,
            f"{base}/official_releases/qt/6.12/CVE-2026-4-qtsvg-6.12.zip.sha256": hashlib.sha256(ZIP).hexdigest().encode(),
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
        self.assertEqual({p["module"] for p in report["new_patches"]}, {"qtbase", "qt5compat", "qtsvg"})
        self.assertEqual([p["file"] for p in report["not_built"]], ["CVE-2026-3-qtconnectivity-6.12.diff"])
        self.assertEqual(report["manual_review"], [])
        # the loose diff of CVE-2026-4 is superseded by the zip series, never downloaded
        self.assertEqual([p["file"] for p in report["superseded"]], ["CVE-2026-4-qtsvg-6.12-0001.diff"])
        self.assertNotIn("https://download.qt.io/official_releases/qt/6.12/CVE-2026-4-qtsvg-6.12-0001.diff",
                         self.site.requested)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["new_lines"], [])  # bootstrap: known_lines was null
        lock = json.loads((self.tmp / "patches/6.12/patches.json").read_text())
        # oldest upstream date first
        self.assertEqual([p["file"] for p in lock["patches"]],
                         ["CVE-2026-4-qtsvg-6.12-0001.diff", "CVE-2026-4-qtsvg-6.12-0002.diff",
                          "CVE-2026-2-qtqt5compat-6.12-0001.diff", "CVE-2026-1-qtbase-6.12.diff"])
        self.assertEqual((self.tmp / "patches/6.12/CVE-2026-4-qtsvg-6.12-0001.diff").read_bytes(), b"one")
        zentry = lock["patches"][0]
        self.assertEqual(zentry["archive"], "CVE-2026-4-qtsvg-6.12.zip")
        self.assertEqual(zentry["sha256"], hashlib.sha256(b"one").hexdigest())
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

    def test_missing_checksum_pending_then_error(self):
        base = "https://download.qt.io/official_releases/qt/6.12/"
        del self.site.pages[base + "CVE-2026-1-qtbase-6.12.diff.sha256"]
        recent = dt.datetime.now(dt.timezone.utc).strftime("%d-%b-%Y %H:%M")
        self.site.pages[base] = self.site.pages[base].replace(b"15-Oct-2026 10:57", recent.encode())
        report = self.run_check()
        self.assertEqual([p["file"] for p in report["pending"]], ["CVE-2026-1-qtbase-6.12.diff"])
        self.assertEqual(report["errors"], [])
        self.assertNotIn("CVE-2026-1-qtbase-6.12.diff", self.state["lines"]["6.12"]["files"])
        # an old file without checksum is an error
        self.site.pages[base] = self.site.pages[base].replace(recent.encode(), b"01-Jan-2026 10:00")
        report = self.run_check()
        self.assertTrue(any("no .sha256" in e for e in report["errors"]))

    def test_changed_patch_detected(self):
        self.run_check()
        base = "https://download.qt.io/official_releases/qt/6.12/"
        new = QTBASE_DIFF.replace(b"patched", b"patched v2")
        self.site.pages[base + "CVE-2026-1-qtbase-6.12.diff"] = new
        self.site.pages[base + "CVE-2026-1-qtbase-6.12.diff.sha256"] = hashlib.sha256(new).hexdigest().encode()
        self.site.pages[base] = self.site.pages[base].replace(b"15-Oct-2026 10:57", b"22-Oct-2026 08:00")
        report = self.run_check()
        self.assertEqual([p["file"] for p in report["changed_patches"]], ["CVE-2026-1-qtbase-6.12.diff"])


    def test_zip_replaces_previously_staged_loose_diffs(self):
        # a loose diff staged by an earlier run, before the zip existed
        check_upstream.stage_patch(self.tmp / "patches", "6.12", {
            "file": "CVE-2026-4-qtsvg-6.12-0001.diff", "cve": "CVE-2026-4", "module": "qtsvg",
            "sha256": "x", "source": "loose"}, b"old loose")
        check_upstream.stage_patch(self.tmp / "patches", "6.12", {
            "file": "CVE-2026-4-qtsvg-6.12-0009.diff", "cve": "CVE-2026-4", "module": "qtsvg",
            "sha256": "y", "source": "loose"}, b"old loose 9")
        self.run_check()
        d = self.tmp / "patches/6.12"
        self.assertFalse((d / "CVE-2026-4-qtsvg-6.12-0009.diff").exists())
        self.assertEqual((d / "CVE-2026-4-qtsvg-6.12-0001.diff").read_bytes(), b"one")
        lock = json.loads((d / "patches.json").read_text())
        names = [p["file"] for p in lock["patches"]]
        self.assertEqual(names[:2], ["CVE-2026-4-qtsvg-6.12-0001.diff", "CVE-2026-4-qtsvg-6.12-0002.diff"])

    def test_zip_with_unexpected_member_needs_review(self):
        bad = make_zip([("../evil.diff", b"x")])
        base = "https://download.qt.io/official_releases/qt/6.12/"
        self.site.pages[base + "CVE-2026-4-qtsvg-6.12.zip"] = bad
        self.site.pages[base + "CVE-2026-4-qtsvg-6.12.zip.sha256"] = hashlib.sha256(bad).hexdigest().encode()
        report = self.run_check()
        self.assertEqual([p["file"] for p in report["manual_review"]], ["CVE-2026-4-qtsvg-6.12.zip"])
        self.assertFalse((self.tmp / "patches/6.12/evil.diff").exists())


class ApplyPatchesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.src = self.tmp / "qt-everywhere-src-6.12.0"
        (self.src / "qtbase/src").mkdir(parents=True)
        (self.src / "qtbase/src/hello.txt").write_text("hello\n")
        self.pdir = self.tmp / "patches/6.12"
        self.pdir.mkdir(parents=True)
        (self.pdir / "a.diff").write_bytes(QTBASE_DIFF)
        self.write_lock([{"file": "a.diff", "module": "qtbase", "cve": "CVE-1", "sha256": SHA, "source": "https://example.invalid/a.diff"}])

    def write_lock(self, patches):
        (self.pdir / "patches.json").write_text(json.dumps({"line": "6.12", "patches": patches}))

    def run_apply(self, modules="qtbase"):
        return apply_patches.main(["--src", str(self.src), "--line", "6.12", "--qt-version", "6.12.0", "--modules", modules,
                                   "--patches-dir", str(self.tmp / "patches"),
                                   "--report", str(self.tmp / "report.md"),
                                   "--json-report", str(self.tmp / "report.json")])

    def test_json_report_feeds_sbom(self):
        self.assertEqual(self.run_apply(), 0)
        (self.tmp / "vcpkg.txt").write_text("openssl:x64-linux   3.5.2#1   TLS/SSL and crypto library\n")
        out = self.tmp / "extras.cdx.json"
        make_sbom_extras.main(["--package", "qt-6.12.0-1-ubuntu2204", "--qt-version", "6.12.0",
                               "--source-url", "https://example.invalid/qt.tar.xz", "--source-sha256", "0" * 64,
                               "--patches", str(self.tmp / "report.json"),
                               "--vcpkg-list", str(self.tmp / "vcpkg.txt"), "--output", str(out)])
        bom = json.loads(out.read_text())
        self.assertEqual(bom["specVersion"], "1.6")
        qt, openssl = bom["components"]
        self.assertEqual(openssl["version"], "3.5.2")
        self.assertEqual([p["resolves"][0]["id"] for p in qt["pedigree"]["patches"]], ["CVE-1"])

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

    def test_conflict_needs_decision_then_skip(self):
        (self.src / "qtbase/src/hello.txt").write_text("something else\n")
        self.assertEqual(self.run_apply(), 1)
        self.write_lock([{"file": "a.diff", "module": "qtbase", "cve": "CVE-1", "sha256": SHA,
                          "source": "s", "versions": {"6.12.0": {"action": "skip", "reason": "fixed differently"}}}])
        self.assertEqual(self.run_apply(), 0)
        self.assertIn("| skipped | fixed differently |", (self.tmp / "report.md").read_text())

    def test_decision_for_other_version_is_ignored(self):
        (self.src / "qtbase/src/hello.txt").write_text("something else\n")
        self.write_lock([{"file": "a.diff", "module": "qtbase", "cve": "CVE-1", "sha256": SHA,
                          "source": "s", "versions": {"6.12.1": {"action": "skip", "reason": "x"}}}])
        self.assertEqual(self.run_apply(), 1)

    def test_apply_with_reduced_context(self):
        diff = (b"diff --git a/src/f.txt b/src/f.txt\n--- a/src/f.txt\n+++ b/src/f.txt\n"
                b"@@ -1,3 +1,3 @@\n ctx1\n-old\n+new\n ctx3\n")
        (self.src / "qtbase/src/f.txt").write_text("CHANGED\nold\nctx3\n")
        (self.pdir / "a.diff").write_bytes(diff)
        sha = hashlib.sha256(diff).hexdigest()
        self.write_lock([{"file": "a.diff", "module": "qtbase", "cve": "CVE-1", "sha256": sha, "source": "s"}])
        self.assertEqual(self.run_apply(), 1)
        self.write_lock([{"file": "a.diff", "module": "qtbase", "cve": "CVE-1", "sha256": sha, "source": "s",
                          "versions": {"6.12.0": {"action": "apply", "min_context": 0, "reason": "ctx drift"}}}])
        self.assertEqual(self.run_apply(), 0)
        self.assertEqual((self.src / "qtbase/src/f.txt").read_text(), "CHANGED\nnew\nctx3\n")

    def test_backport_replaces_upstream_patch(self):
        (self.src / "qtbase/src/hello.txt").write_text("hello\nmore\n")
        upstream = (b"diff --git a/src/hello.txt b/src/hello.txt\n--- a/src/hello.txt\n+++ b/src/hello.txt\n"
                    b"@@ -1,2 +1,2 @@\n-hello\n+hello, patched\n different\n")
        (self.pdir / "a.diff").write_bytes(upstream)
        (self.pdir / "backports").mkdir()
        bp = (b"diff --git a/src/hello.txt b/src/hello.txt\n--- a/src/hello.txt\n+++ b/src/hello.txt\n"
              b"@@ -1,2 +1,2 @@\n-hello\n+hello, patched\n more\n")
        (self.pdir / "backports/a-backport.diff").write_bytes(bp)
        entry = {"file": "a.diff", "module": "qtbase", "cve": "CVE-1", "source": "s",
                 "sha256": hashlib.sha256(upstream).hexdigest()}
        self.write_lock([entry])
        self.assertEqual(self.run_apply(), 1)  # upstream conflicts
        entry["versions"] = {"6.12.0": {"action": "backport", "file": "backports/a-backport.diff",
                                        "sha256": hashlib.sha256(bp).hexdigest(), "reason": "context"}}
        self.write_lock([entry])
        self.assertEqual(self.run_apply(), 0)
        self.assertEqual((self.src / "qtbase/src/hello.txt").read_text(), "hello, patched\nmore\n")
        self.assertIn("applied (backport)", (self.tmp / "report.md").read_text())
        # tampered backport is refused
        (self.pdir / "backports/a-backport.diff").write_bytes(bp + b" \n")
        self.assertEqual(self.run_apply(), 1)

    def test_orphan_backport_fails(self):
        (self.pdir / "backports").mkdir()
        (self.pdir / "backports/x.diff").write_bytes(b"x")
        self.assertEqual(self.run_apply(), 1)

    def test_decision_without_reason_is_rejected(self):
        self.write_lock([{"file": "a.diff", "module": "qtbase", "cve": "CVE-1", "sha256": SHA,
                          "source": "s", "versions": {"6.12.0": {"action": "skip"}}}])
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


class ComparePatchSetsTest(unittest.TestCase):
    def write(self, name, patches):
        path = Path(tempfile.mkdtemp()) / name
        path.write_text(json.dumps({"patches": patches}))
        return str(path)

    def test_same_and_different(self):
        a = {"file": "a.diff", "sha256": "1", "status": "applied"}
        b = {"file": "b.diff", "sha256": "2", "status": "applied (backport)"}
        skipped = {"file": "c.diff", "sha256": "3", "status": "already in this release"}
        prev = self.write("prev.json", [a, skipped])
        self.assertEqual(compare_patch_sets.main([prev, self.write("n1.json", [a])]), 0)
        self.assertEqual(compare_patch_sets.main([prev, self.write("n2.json", [a, b])]), 1)
        changed = {**a, "sha256": "9"}
        self.assertEqual(compare_patch_sets.main([prev, self.write("n3.json", [changed])]), 1)


if __name__ == "__main__":
    unittest.main()
