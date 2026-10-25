# Security patches

Upstream Qt publishes fixes for security issues as `.diff`/`.patch` files in
each release directory on download.qt.io (e.g.
`https://download.qt.io/official_releases/qt/6.12/`), often long before the
next open-source patch release, and for 6.8 LTS in place of releases.

Layout: one directory per LTS line, applied to every release of that line.

```
patches/
  6.8/
    patches.json                      # the lock file: what to apply, in order
    CVE-2025-3512-qtbase-6.8.diff
    ...
```

`patches.json` entries:

| field | meaning |
|---|---|
| `file` | file name in this directory |
| `cve` | CVE identifier |
| `module` | Qt submodule directory the patch applies to (`-p1` inside it) |
| `sha256` | hash of the reviewed file; the build fails on any mismatch |
| `source` | where it was downloaded from |

## How patches get here

1. `check-upstream.yml` runs daily, finds new or changed patches for modules
   we build, downloads them, checks them against the `.sha256` that
   download.qt.io publishes, and opens a pull request adding them here.
2. **A human reviews the diffs and merges the PR.**
3. The merge triggers a rebuild of the latest release of that line (draft
   release, package release number bumped).

At build time `scripts/apply_patches.py`:

- refuses any patch file not listed in `patches.json`, or whose hash differs
- skips patches for modules not being built
- skips patches already contained in the Qt release being built (detected by
  checking that the patch applies in reverse)
- fails the build if a patch neither applies nor is already present

The result of every patch ends up in the release notes.

To drop a patch, remove its file and its `patches.json` entry in the same commit.
