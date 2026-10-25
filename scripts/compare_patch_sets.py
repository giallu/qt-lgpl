#!/usr/bin/env python3
"""Compare the patches applied in two apply_patches.py JSON reports.

    compare_patch_sets.py <previous report> <new report>

Exit status 0 if the same patches (same files, same SHA-256, same order)
are applied in both, 1 if they differ. Used to skip automatic rebuilds
that would produce exactly the same packages.
"""

import json
import sys


def applied(path):
    report = json.load(open(path))
    return [(p["file"], p.get("sha256"), p["status"]) for p in report.get("patches", [])
            if str(p.get("status", "")).startswith("applied")]


def main(argv=None):
    prev_path, new_path = (argv or sys.argv[1:])[:2]
    prev, new = applied(prev_path), applied(new_path)
    if prev == new:
        print(f"Same {len(new)} applied patches as the previous release.")
        return 0
    print("Applied patches differ from the previous release:")
    for item in sorted(set(new) - set(prev)):
        print(f"  + {item[0]} ({item[2]})")
    for item in sorted(set(prev) - set(new)):
        print(f"  - {item[0]} ({item[2]})")
    if set(prev) == set(new):
        print("  (same patches, different order)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
