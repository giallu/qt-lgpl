#!/usr/bin/env python3
"""Apply the reviewed security patches in patches/<line>/ to a Qt source tree.

Rules, so nothing unreviewed reaches a build:

* only files listed in patches/<line>/patches.json are applied, and each must
  match the SHA-256 recorded there (the file is merged through a reviewed PR)
* any .diff/.patch in the directory that is NOT listed fails the build
* patches for modules that are not being built are skipped
* a patch whose reverse applies cleanly is already part of this Qt release
  (common for older patches vs. newer patch releases) and is skipped
* a patch that neither applies nor is already present fails the build

Writes a markdown report suitable for release notes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

PATCH_SUFFIXES = (".diff", ".patch")


def git_apply(module_dir: Path, patch: Path, *extra: str) -> bool:
    env = dict(os.environ)
    # The source tree is extracted inside the repository checkout. Stop git
    # from discovering that repository, otherwise `git apply` would resolve
    # paths against the checkout root and silently skip every hunk.
    env["GIT_CEILING_DIRECTORIES"] = str(module_dir.parent.resolve())
    result = subprocess.run(
        ["git", "apply", "-p1", "--whitespace=nowarn", *extra, str(patch.resolve())],
        cwd=module_dir, env=env, capture_output=True, text=True,
    )
    if result.returncode != 0 and "--check" not in extra:
        sys.stderr.write(result.stderr)
    return result.returncode == 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--src", required=True, type=Path, help="qt-everywhere-src-X.Y.Z directory")
    parser.add_argument("--line", required=True, help="LTS line, e.g. 6.8")
    parser.add_argument("--modules", required=True, help="comma separated submodules being built")
    parser.add_argument("--patches-dir", default="patches", type=Path)
    parser.add_argument("--report", type=Path, help="write a markdown report here")
    parser.add_argument("--json-report", type=Path, help="write a JSON report here (used for the SBOM)")
    args = parser.parse_args(argv)

    line_dir = args.patches_dir / args.line
    lock_path = line_dir / "patches.json"
    modules = {m.strip() for m in args.modules.split(",") if m.strip()}
    rows: list[tuple[str, str, str, str]] = []
    results: list[dict] = []

    if not lock_path.exists():
        unlisted = sorted(p.name for p in line_dir.glob("*") if p.suffix in PATCH_SUFFIXES) if line_dir.exists() else []
        if unlisted:
            print(f"error: patch files without {lock_path}: {', '.join(unlisted)}", file=sys.stderr)
            return 1
        print(f"No patches for Qt {args.line}.")
        if args.report:
            args.report.write_text(f"No security patches applied on top of upstream Qt {args.line}.\n")
        if args.json_report:
            args.json_report.write_text(json.dumps({"line": args.line, "patches": []}) + "\n")
        return 0

    lock = json.loads(lock_path.read_text())
    listed = {p["file"] for p in lock.get("patches", [])}
    unlisted = sorted(p.name for p in line_dir.iterdir() if p.suffix in PATCH_SUFFIXES and p.name not in listed)
    if unlisted:
        print(f"error: patch files not listed in {lock_path}: {', '.join(unlisted)}", file=sys.stderr)
        return 1

    failed = False
    for entry in lock.get("patches", []):
        name, module, cve = entry["file"], entry["module"], entry.get("cve", "")
        patch = line_dir / name
        if not patch.exists():
            print(f"error: {name} listed but missing", file=sys.stderr)
            return 1
        digest = hashlib.sha256(patch.read_bytes()).hexdigest()
        if digest != entry["sha256"]:
            print(f"error: {name} sha256 {digest} does not match patches.json {entry['sha256']}", file=sys.stderr)
            return 1

        module_dir = args.src / module
        if module not in modules:
            status = "skipped (module not built)"
        elif not module_dir.is_dir():
            status = "FAILED (module directory missing)"
            failed = True
        elif git_apply(module_dir, patch, "--check"):
            status = "applied" if git_apply(module_dir, patch) else "FAILED"
            failed |= status == "FAILED"
        elif git_apply(module_dir, patch, "--check", "--reverse"):
            status = "already in this release"
        else:
            git_apply(module_dir, patch, "--check")  # rerun to print the reason
            status = "FAILED (does not apply)"
            failed = True
        print(f"{status:<28} {name}")
        rows.append((cve, module, name, status))
        results.append({**entry, "status": status})

    if args.report:
        lines = [
            f"Security patches from `patches/{args.line}/` (verified by SHA-256):",
            "",
            "| CVE | Module | Patch | Result |",
            "|---|---|---|---|",
            *[f"| {c} | {m} | `{n}` | {s} |" for c, m, n, s in rows],
            "",
        ]
        args.report.write_text("\n".join(lines))
    if args.json_report:
        args.json_report.write_text(json.dumps({"line": args.line, "patches": results}, indent=2) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
