#!/usr/bin/env python3
"""Apply the reviewed security patches in patches/<line>/ to a Qt source tree.

Rules, so nothing unreviewed reaches a build:

* only files listed in patches/<line>/patches.json are applied, and each must
  match the SHA-256 recorded there (the file is merged through a reviewed PR)
* any .diff/.patch in the directory that is NOT listed fails the build
* patches for modules that are not being built are skipped
* a patch whose reverse applies cleanly is already part of this Qt release
  (common for older patches vs. newer patch releases) and is skipped
* a patch that neither applies nor is already present fails the build,
  unless patches.json records a reviewed decision for this Qt version:

      "versions": {
        "6.8.5": {"action": "skip", "reason": "already included in a different form ..."},
        "6.8.6": {"action": "apply", "min_context": 1, "recount": true, "reason": "..."}
      }

        "6.8.5": {"action": "backport", "file": "backports/<name>.diff", "sha256": "...", "reason": "..."}

  "backport" applies our own adaptation of the patch to that Qt version
  instead (stored in patches/<line>/backports/, checked against its sha256,
  applied strictly). "skip" leaves the patch out; "apply" applies it with reduced context
  (git apply -C<n>, the equivalent of patch's fuzz) and/or --recount (for
  upstream files with wrong hunk line counts). Decisions are per Qt version,
  so every new release is checked again from scratch.

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
    parser.add_argument("--qt-version", required=True, help="Qt version being built, e.g. 6.8.5")
    parser.add_argument("--modules", required=True, help="comma separated submodules being built")
    parser.add_argument("--patches-dir", default="patches", type=Path)
    parser.add_argument("--report", type=Path, help="write a markdown report here")
    parser.add_argument("--json-report", type=Path, help="write a JSON report here (used for the SBOM)")
    args = parser.parse_args(argv)

    line_dir = args.patches_dir / args.line
    lock_path = line_dir / "patches.json"
    modules = {m.strip() for m in args.modules.split(",") if m.strip()}
    rows: list[tuple[str, str, str, str, str]] = []
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
    referenced = {d.get("file") for e in lock.get("patches", []) for d in e.get("versions", {}).values()
                  if d.get("action") == "backport"}
    backport_dir = line_dir / "backports"
    if backport_dir.is_dir():
        orphans = sorted(f"backports/{p.name}" for p in backport_dir.iterdir()
                         if p.suffix in PATCH_SUFFIXES and f"backports/{p.name}" not in referenced)
        if orphans:
            print(f"error: backports not referenced by any decision: {', '.join(orphans)}", file=sys.stderr)
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

        decision = entry.get("versions", {}).get(args.qt_version)
        if decision is not None:
            if decision.get("action") not in ("skip", "apply", "backport") or not decision.get("reason"):
                print(f"error: {name}: decision for {args.qt_version} needs action skip|apply|backport "
                      "and a reason", file=sys.stderr)
                return 1
            if decision["action"] == "backport":
                bp = line_dir / str(decision.get("file", ""))
                if not str(decision.get("file", "")).startswith("backports/") or not bp.is_file():
                    print(f"error: {name}: backport file {decision.get('file')!r} missing", file=sys.stderr)
                    return 1
                bp_digest = hashlib.sha256(bp.read_bytes()).hexdigest()
                if bp_digest != decision.get("sha256"):
                    print(f"error: {decision['file']} sha256 {bp_digest} does not match the decision "
                          f"{decision.get('sha256')}", file=sys.stderr)
                    return 1
        options: list[str] = []
        note = ""
        if decision and decision["action"] == "apply":
            if decision.get("min_context") is not None:
                options.append(f"-C{int(decision['min_context'])}")
            if decision.get("recount"):
                options.append("--recount")
        if decision:
            note = decision["reason"] + (f" [{' '.join(options)}]" if options else "")

        module_dir = args.src / module
        if module not in modules:
            status = "skipped (module not built)"
        elif not module_dir.is_dir():
            status = "FAILED (module directory missing)"
            failed = True
        elif decision and decision["action"] == "skip":
            status = "skipped"
        elif decision and decision["action"] == "backport":
            bp = line_dir / decision["file"]
            if git_apply(module_dir, bp, "--check") and git_apply(module_dir, bp):
                status = "applied (backport)"
                note = f"{decision['reason']} [{decision['file']}]"
            else:
                status = "FAILED (backport does not apply)"
                failed = True
        elif git_apply(module_dir, patch, "--check", *options):
            status = "applied" if git_apply(module_dir, patch, *options) else "FAILED"
            failed |= status == "FAILED"
        elif git_apply(module_dir, patch, "--check", "--reverse", *options):
            status = "already in this release"
        else:
            git_apply(module_dir, patch, "--check", *options)  # rerun to print the reason
            status = "FAILED (does not apply)"
            note = note or f"needs a reviewed decision for Qt {args.qt_version} in patches.json"
            failed = True
        print(f"{status:<28} {name}" + (f"  ({note})" if note else ""))
        rows.append((cve, module, name, status, note))
        results.append({**{k: v for k, v in entry.items() if k != "versions"}, "status": status, "note": note})

    if args.report:
        lines = [
            f"Security patches from `patches/{args.line}/` (verified by SHA-256):",
            "",
            "| CVE | Module | Patch | Result | Review note |",
            "|---|---|---|---|---|",
            *[f"| {c} | {m} | `{n}` | {s} | {t} |" for c, m, n, s, t in rows],
            "",
        ]
        args.report.write_text("\n".join(lines))
    if args.json_report:
        args.json_report.write_text(json.dumps({"line": args.line, "patches": results}, indent=2) + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
