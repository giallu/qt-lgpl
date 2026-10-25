#!/usr/bin/env python3
"""Write a CycloneDX 1.6 SBOM for what Qt's own SBOMs do not cover.

Qt generates SBOMs for itself and its bundled third-party code (configure
-sbom). This document adds what this repository puts on top:

* the upstream Qt source archive and its verified SHA-256
* the CVE patches applied to it (as pedigree patches, with the CVE they resolve)
* OpenSSL, built by vcpkg and linked into QtNetwork

Standard library only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import uuid
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--package", required=True, help="package name, e.g. qt-6.12.0-1-ubuntu2204")
    p.add_argument("--qt-version", required=True)
    p.add_argument("--source-url", required=True)
    p.add_argument("--source-sha256", required=True)
    p.add_argument("--patches", type=Path, help="JSON report written by apply_patches.py")
    p.add_argument("--vcpkg-list", type=Path, help="output of `vcpkg list openssl`")
    p.add_argument("--repo", default="giallu/qt-lgpl")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args(argv)

    applied = []
    if args.patches and args.patches.exists():
        report = json.loads(args.patches.read_text())
        applied = [x for x in report.get("patches", []) if x.get("status") == "applied"]

    qt = {
        "type": "framework",
        "bom-ref": "qt",
        "name": "qt-everywhere-src",
        "version": args.qt_version,
        "purl": f"pkg:generic/qt@{args.qt_version}?download_url={args.source_url}",
        "licenses": [{"expression": "LGPL-3.0-only"}],
        "hashes": [{"alg": "SHA-256", "content": args.source_sha256}],
        "externalReferences": [{"type": "distribution", "url": args.source_url}],
    }
    if applied:
        qt["pedigree"] = {"patches": [
            {
                "type": "backport",
                "diff": {"url": x["source"]},
                "resolves": [{"type": "security", "id": x["cve"],
                              "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{x['cve']}"}}],
            }
            for x in applied
        ]}

    components = [qt]
    if args.vcpkg_list and args.vcpkg_list.exists():
        # "openssl:x64-linux    3.5.2#1    TLS/SSL and crypto library ..."
        m = re.search(r"^openssl:(\S+)\s+([0-9][^\s#]*)", args.vcpkg_list.read_text(), re.MULTILINE)
        if m:
            triplet, version = m.groups()
            components.append({
                "type": "library",
                "bom-ref": "openssl",
                "name": "openssl",
                "version": version,
                "purl": f"pkg:generic/openssl@{version}",
                "licenses": [{"expression": "Apache-2.0"}],
                "description": f"Built with vcpkg ({triplet}), statically linked into QtNetwork",
            })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "component": {
                "type": "framework",
                "bom-ref": "package",
                "name": args.package,
                "version": args.qt_version,
                "externalReferences": [{"type": "vcs", "url": f"https://github.com/{args.repo}"}],
            },
            "tools": {"components": [{"type": "application", "name": "qt-lgpl make_sbom_extras.py"}]},
        },
        "components": components,
        "dependencies": [{"ref": "package", "dependsOn": [c["bom-ref"] for c in components]},
                         {"ref": "qt", "dependsOn": ["openssl"] if len(components) > 1 else []}],
    }
    args.output.write_text(json.dumps(bom, indent=2) + "\n")
    print(f"wrote {args.output} ({len(applied)} applied patches, {len(components)} components)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
