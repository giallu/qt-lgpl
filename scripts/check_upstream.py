#!/usr/bin/env python3
"""Watch download.qt.io for new LTS patch releases and security patches.

Compares the upstream directory listings of every tracked LTS line with
config/upstream-state.json and reports what changed:

* new patch releases (e.g. 6.12.1) -> listed in the summary, optionally built
* new or changed CVE patches for modules we build -> verified against the
  SHA-256 published by download.qt.io and staged in patches/<line>/ so they
  can be reviewed in a pull request
* zip archives of CVE patches for modules we build -> verified, unpacked and
  staged like plain patches, in archive order. Upstream sometimes publishes
  an updated, complete series as a zip next to older loose diffs of the same
  CVE: the zip supersedes those loose diffs.
* CVE patches for modules we do not build -> listed in the summary for
  information
* new minor lines (e.g. 6.13) -> listed so a human can decide whether to track

Nothing downloaded here is ever applied to a build directly: staged patches
only take effect once the pull request that adds them is merged.

Only the standard library is used, so it runs on any runner without setup.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import io
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

BASE_URL = "https://download.qt.io"
LOCATIONS = ("official_releases", "archive")  # official first: preferred source
KEEPALIVE_DAYS = 25  # GitHub disables scheduled workflows after 60 idle days
# download.qt.io computes checksums asynchronously: a file published minutes
# ago may not have its .sha256 yet. Wait this long before calling it an error.
CHECKSUM_GRACE_HOURS = 48
USER_AGENT = "qt-lgpl-upstream-check (+https://github.com/giallu/qt-lgpl)"

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
LINE_RE = re.compile(r"^(\d+)\.(\d+)$")
DATE_RE = re.compile(r"(\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2})")
HREF_RE = re.compile(r"<a\s+[^>]*href=\"([^\"]+)\"", re.IGNORECASE)
# CVE-2026-8168-qtsvg-6.8-0001.diff, CVE-2025-6338-qtbase-6.8.patch, ...
CVE_FILE_RE = re.compile(
    r"^(?P<cve>CVE-\d{4}-\d+)-(?P<module>.+?)-(?P<line>\d+\.\d+)"
    r"(?:-(?P<part>\d+))?\.(?P<ext>diff|patch|zip)$"
)
SHA256_RE = re.compile(r"\b([0-9a-f]{64})\b")
MEMBER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.(diff|patch)$")


# --------------------------------------------------------------------------
# network helpers (module level so tests can replace them)

def fetch(url: str) -> bytes | None:
    """Return the body of url, or None on 404."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def fetch_published_sha256(url: str) -> str | None:
    """download.qt.io (MirrorBrain) serves <file>.sha256 from its own host."""
    body = fetch(url + ".sha256")
    if not body:
        return None
    match = SHA256_RE.search(body.decode("utf-8", "replace").lower())
    return match.group(1) if match else None


# --------------------------------------------------------------------------
# parsing

def parse_listing(html: str) -> list[tuple[str, bool, str | None]]:
    """Return (name, is_dir, date) for each entry of an Apache/MirrorBrain index."""
    entries: dict[str, tuple[str, bool, str | None]] = {}
    for match in HREF_RE.finditer(html):
        href = match.group(1)
        if "?" in href or href.startswith(("mailto:", "#")):
            continue
        is_dir = href.endswith("/")
        name = href.rstrip("/").rsplit("/", 1)[-1]
        if not name or name in (".", ".."):
            continue
        date_match = DATE_RE.search(html, match.end(), match.end() + 400)
        date = date_match.group(1) if date_match else None
        entries.setdefault(name, (name, is_dir, date))
    return list(entries.values())


def version_key(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in version.split("."))


def date_key(date: str | None) -> dt.datetime:
    if not date:
        return dt.datetime.min
    return dt.datetime.strptime(date, "%d-%b-%Y %H:%M")


def resolve_module(token: str, submodules: list[str]) -> tuple[str, bool]:
    """Map the module token of a CVE file name to a Qt submodule directory.

    Upstream is not consistent: the same module appears as both
    'qt5compat' and 'qtqt5compat'.
    """
    if token in submodules:
        return token, True
    if token.startswith("qt") and token[2:] in submodules:
        return token[2:], True
    guess = token[2:] if token.startswith("qtqt") else token
    return guess, False


# --------------------------------------------------------------------------
# core

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def zip_members(data: bytes) -> list[tuple[str, bytes]]:
    """Return the (name, content) of the diffs in a zip, sorted by name.

    macOS metadata (__MACOSX/, ._*) is ignored; any other unexpected member,
    or an unsafe name, raises ValueError so a human looks at the archive.
    """
    members = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            parts = info.filename.split("/")
            if parts[0] == "__MACOSX" or parts[-1].startswith("._"):
                continue
            name = parts[-1]
            if len(parts) != 1 or not MEMBER_RE.match(name):
                raise ValueError(f"unexpected member {info.filename!r}")
            members.append((name, zf.read(info)))
    if not members:
        raise ValueError("no .diff/.patch files inside")
    names = [n for n, _ in members]
    if len(set(names)) != len(names):
        raise ValueError("duplicate member names")
    return sorted(members)


def load_lock(patches_dir: Path, line: str) -> tuple[Path, dict]:
    lock_path = patches_dir / line / "patches.json"
    lock = {"line": line, "patches": []}
    if lock_path.exists():
        lock = json.loads(lock_path.read_text())
    lock.setdefault("patches", [])
    return lock_path, lock


def stage_patch_set(patches_dir: Path, line: str, cve: str, staged: list[tuple[dict, bytes]]) -> list[str]:
    """Replace every staged patch of `cve` with the members of an archive.

    The new entries take the place of the first replaced entry (keeping the
    position in the apply order). Returns the names of entries removed.
    """
    line_dir = patches_dir / line
    line_dir.mkdir(parents=True, exist_ok=True)
    lock_path, lock = load_lock(patches_dir, line)
    patches = lock["patches"]
    positions = [i for i, e in enumerate(patches) if e.get("cve") == cve]
    removed = [patches[i]["file"] for i in positions]
    insert_at = positions[0] if positions else len(patches)
    patches[:] = [e for e in patches if e.get("cve") != cve]
    new_names = {entry["file"] for entry, _ in staged}
    for name in removed:
        if name not in new_names:
            (line_dir / name).unlink(missing_ok=True)
    for entry, data in staged:
        (line_dir / entry["file"]).write_bytes(data)
    patches[insert_at:insert_at] = [entry for entry, _ in staged]
    lock_path.write_text(json.dumps(lock, indent=2) + "\n")
    return removed


def stage_patch(patches_dir: Path, line: str, entry: dict, data: bytes) -> None:
    line_dir = patches_dir / line
    line_dir.mkdir(parents=True, exist_ok=True)
    (line_dir / entry["file"]).write_bytes(data)

    lock_path = line_dir / "patches.json"
    lock = {"line": line, "patches": []}
    if lock_path.exists():
        lock = json.loads(lock_path.read_text())
    patches = lock.setdefault("patches", [])
    for i, existing in enumerate(patches):
        if existing["file"] == entry["file"]:
            patches[i] = entry
            break
    else:
        patches.append(entry)
    lock_path.write_text(json.dumps(lock, indent=2) + "\n")


def missing_checksum(report: dict, info: dict, date: str | None) -> None:
    """No .sha256 published: pending while the file is new, an error afterwards.

    Either way the file is not recorded in the state, so the next run retries.
    """
    listed = date_key(date).replace(tzinfo=dt.timezone.utc) if date else None
    age_h = (dt.datetime.now(dt.timezone.utc) - listed).total_seconds() / 3600 if listed else None
    if age_h is not None and age_h < CHECKSUM_GRACE_HOURS:
        report["pending"].append({**info, "listed": date})
    else:
        report["errors"].append(f"{info['file']}: no .sha256 published upstream "
                                f"(listed {date or 'at an unknown date'}), not staged")


def check(config: dict, state: dict, patches_dir: Path) -> dict:
    """Update state in place and return a report of what changed."""
    report: dict[str, list] = {
        "new_versions": [],
        "new_patches": [],
        "changed_patches": [],
        "not_built": [],
        "superseded": [],
        "pending": [],
        "manual_review": [],
        "new_lines": [],
        "errors": [],
    }
    submodules = config["submodules"] + config.get("submodules_windows", [])
    timestamp = now_iso()

    for line in config["lts_lines"]:
        lstate = state.setdefault("lines", {}).setdefault(line, {"versions": [], "files": {}})
        lstate.setdefault("files", {})
        versions: dict[str, str] = {}
        files: dict[str, tuple[str, str | None]] = {}
        listings_ok = 0

        for location in LOCATIONS:
            try:
                body = fetch(f"{BASE_URL}/{location}/qt/{line}/")
            except Exception as exc:  # network trouble: report, keep going
                report["errors"].append(f"{location}/qt/{line}/: {exc}")
                continue
            if body is None:
                continue
            listings_ok += 1
            for name, is_dir, date in parse_listing(body.decode("utf-8", "replace")):
                if is_dir and VERSION_RE.match(name) and name.startswith(line + "."):
                    versions.setdefault(name, location)
                elif not is_dir and CVE_FILE_RE.match(name):
                    files.setdefault(name, (location, date))

        if not listings_ok:
            report["errors"].append(f"no listing found for Qt {line}")
            continue

        # ---- releases
        seen = set(lstate.get("versions", []))
        latest = max(versions, key=version_key) if versions else None
        for version in sorted(set(versions) - seen, key=version_key):
            report["new_versions"].append({
                "line": line,
                "version": version,
                "location": versions[version],
                "latest": version == latest,
            })
        lstate["versions"] = sorted(seen | set(versions), key=version_key)

        # CVEs published as a zip (for a module we build) supersede loose diffs
        zip_for_cve: dict[str, str] = {}
        for name in files:
            m = CVE_FILE_RE.match(name)
            if m["ext"] == "zip" and resolve_module(m["module"], submodules)[1]:
                zip_for_cve[m["cve"]] = name

        # ---- CVE files, oldest first so patches.json keeps upstream order
        for name, (location, date) in sorted(files.items(), key=lambda kv: (date_key(kv[1][1]), kv[0])):
            match = CVE_FILE_RE.match(name)
            assert match
            module, built = resolve_module(match["module"], submodules)
            url = f"{BASE_URL}/{location}/qt/{line}/{name}"
            prev = lstate["files"].get(name)
            info = {"line": line, "file": name, "cve": match["cve"], "module": module, "url": url}

            if match["ext"] == "zip" and built:
                # "archive" is how older versions of this script recorded zips (unprocessed)
                if prev and prev.get("kind") == "patchset" and prev.get("upstream_date") == date:
                    continue
                try:
                    published = fetch_published_sha256(url)
                    if prev and prev.get("kind") == "patchset" and published == prev.get("sha256"):
                        prev["upstream_date"] = date
                        continue
                    data = fetch(url)
                except Exception as exc:
                    report["errors"].append(f"{name}: {exc}")
                    continue
                if data is None:
                    report["errors"].append(f"{name}: listed but not downloadable")
                    continue
                if published is None:
                    missing_checksum(report, info, date)
                    continue
                actual = hashlib.sha256(data).hexdigest()
                if actual != published:
                    report["errors"].append(
                        f"{name}: SHA-256 mismatch (downloaded {actual}, published {published}), not staged")
                    continue
                try:
                    members = zip_members(data)
                except (ValueError, zipfile.BadZipFile) as exc:
                    report["errors"].append(f"{name}: {exc}; review it manually")
                    report["manual_review"].append(info)
                    continue
                staged = []
                for member, content in members:
                    staged.append(({
                        "file": member,
                        "cve": match["cve"],
                        "module": module,
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "source": f"{url}#{member}",
                        "archive": name,
                        "archive_sha256": actual,
                        "upstream_date": date,
                        "added": timestamp,
                    }, content))
                removed = stage_patch_set(patches_dir, line, match["cve"], staged)
                lstate["files"][name] = {
                    "kind": "patchset", "module": module, "sha256": actual, "upstream_date": date,
                    "members": [m for m, _ in members],
                    "first_seen": prev.get("first_seen", timestamp) if prev else timestamp,
                }
                for entry, _ in staged:
                    report["changed_patches" if prev and prev.get("kind") == "patchset" else "new_patches"].append(
                        {**info, "file": entry["file"], "sha256": entry["sha256"], "archive": name})
                for old in removed:
                    if old not in {e["file"] for e, _ in staged}:
                        report["superseded"].append({**info, "file": old, "by": name})
                continue

            if match["ext"] != "zip" and match["cve"] in zip_for_cve:
                if not prev or prev.get("kind") != "superseded":
                    lstate["files"][name] = {"kind": "superseded", "by": zip_for_cve[match["cve"]],
                                             "upstream_date": date,
                                             "first_seen": prev.get("first_seen", timestamp) if prev else timestamp}
                    if prev is None:
                        report["superseded"].append({**info, "by": zip_for_cve[match["cve"]]})
                continue

            if not built:
                if prev is None:
                    lstate["files"][name] = {"kind": "not-built", "module": module,
                                             "upstream_date": date, "first_seen": timestamp}
                    report["not_built"].append(info)
                continue

            # A built module: only (re)download when new or when the upstream date moved.
            if prev and prev.get("sha256") and prev.get("upstream_date") == date:
                continue
            try:
                published = fetch_published_sha256(url)
                if prev and prev.get("sha256") and published == prev["sha256"]:
                    prev["upstream_date"] = date
                    continue
                data = fetch(url)
            except Exception as exc:
                report["errors"].append(f"{name}: {exc}")
                continue
            if data is None:
                report["errors"].append(f"{name}: listed but not downloadable")
                continue
            actual = hashlib.sha256(data).hexdigest()
            if published is None:
                missing_checksum(report, info, date)
                continue
            if actual != published:
                report["errors"].append(
                    f"{name}: SHA-256 mismatch (downloaded {actual}, published {published}), not staged")
                continue

            entry = {
                "file": name,
                "cve": match["cve"],
                "module": module,
                "sha256": actual,
                "source": url,
                "upstream_date": date,
                "added": timestamp,
            }
            stage_patch(patches_dir, line, entry, data)
            lstate["files"][name] = {
                "kind": "patch",
                "module": module,
                "sha256": actual,
                "upstream_date": date,
                "first_seen": prev.get("first_seen", timestamp) if prev else timestamp,
            }
            info["sha256"] = actual
            report["changed_patches" if prev else "new_patches"].append(info)

    # ---- new minor lines
    try:
        body = fetch(f"{BASE_URL}/official_releases/qt/")
        if body:
            lines = {n for n, is_dir, _ in parse_listing(body.decode("utf-8", "replace"))
                     if is_dir and LINE_RE.match(n)}
            known = state.get("known_lines")
            if known is not None:
                for new_line in sorted(lines - set(known), key=version_key):
                    if new_line not in config["lts_lines"]:
                        report["new_lines"].append(new_line)
            state["known_lines"] = sorted(set(known or []) | lines, key=version_key)
    except Exception as exc:
        report["errors"].append(f"official_releases/qt/: {exc}")

    return report


def builds_to_dispatch(config: dict, report: dict) -> list[str]:
    if not config.get("auto_build_new_versions"):
        return []
    return [v["version"] for v in report["new_versions"] if v["latest"]]


def render_summary(report: dict, builds: list[str]) -> str:
    out: list[str] = []

    def section(title: str, rows: list[str]) -> None:
        if rows:
            out.append(f"### {title}\n")
            out.extend(rows)
            out.append("")

    section("New Qt releases", [
        f"- **Qt {v['version']}** ({v['location']})"
        + (" — build started" if v["version"] in builds else "")
        for v in report["new_versions"]])
    section("New security patches for modules we build (staged for review)", [
        f"- `{p['file']}` — {p['cve']}, module `{p['module']}`, sha256 `{p['sha256']}`"
        + (f" (from `{p['archive']}`)" if p.get("archive") else "")
        for p in report["new_patches"]])
    section("Security patches CHANGED upstream (staged for review)", [
        f"- `{p['file']}` — {p['cve']}, module `{p['module']}`, new sha256 `{p['sha256']}`"
        for p in report["changed_patches"]])
    section("Loose patches superseded by a zip series (not used)", [
        f"- `{p['file']}` — superseded by `{p['by']}`" for p in report["superseded"]])
    section("Waiting for upstream checksums (retried automatically)", [
        f"- `{p['file']}` — {p['cve']}, module `{p['module']}`, listed {p['listed']}" for p in report["pending"]])
    section("Need manual review", [
        f"- [{p['file']}]({p['url']}) — {p['cve']}" for p in report["manual_review"]])
    section("Patches for modules we don't build (no action needed)", [
        f"- `{p['file']}` — {p['cve']}, module `{p['module']}`" for p in report["not_built"]])
    section("New Qt minor lines (not tracked — LTS?)", [
        f"- Qt {line}: https://download.qt.io/official_releases/qt/{line}/" for line in report["new_lines"]])
    section("Problems", [f"- {e}" for e in report["errors"]])
    return "\n".join(out) if out else "No upstream changes.\n"


def state_changed(before: dict, after: dict) -> bool:
    strip = lambda s: {k: v for k, v in s.items() if k != "last_committed"}
    return json.dumps(strip(before), sort_keys=True) != json.dumps(strip(after), sort_keys=True)


def needs_keepalive(state: dict) -> bool:
    last = state.get("last_committed")
    if not last:
        return True
    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(last)
    return age.days >= KEEPALIVE_DAYS


def write_github_output(values: dict[str, str]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a") as fh:
        for key, value in values.items():
            fh.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="config/build.json", type=Path)
    parser.add_argument("--state", default="config/upstream-state.json", type=Path)
    parser.add_argument("--patches-dir", default="patches", type=Path)
    parser.add_argument("--summary", type=Path, help="write a markdown summary here")
    parser.add_argument("--report", type=Path, help="write the JSON report here")
    args = parser.parse_args(argv)

    config = json.loads(args.config.read_text())
    state = json.loads(args.state.read_text())
    before = json.loads(json.dumps(state))

    report = check(config, state, args.patches_dir)
    builds = builds_to_dispatch(config, report)

    if state_changed(before, state) or needs_keepalive(before):
        state["last_committed"] = now_iso()
        args.state.write_text(json.dumps(state, indent=2) + "\n")

    summary = render_summary(report, builds)
    print(summary)
    if args.summary:
        args.summary.write_text(summary)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")

    notices = any(report[k] for k in ("new_versions", "manual_review", "new_lines", "not_built", "superseded"))
    write_github_output({
        "patches_staged": str(bool(report["new_patches"] or report["changed_patches"])).lower(),
        "notices": str(notices).lower(),
        "builds": json.dumps(builds),
        "errors": str(bool(report["errors"])).lower(),
    })
    # Fail the run on problems so GitHub's own failure notification fires;
    # state and patches are still written so progress is not lost.
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
