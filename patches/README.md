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
| `source` | where it was downloaded from (`<zip url>#<member>` for patches from a zip) |
| `archive`, `archive_sha256` | the zip a patch came from, and the zip's verified hash |
| `versions` | reviewed decisions per Qt version (see below) |

## Zip archives

Upstream sometimes publishes a CVE fix as a zip with a whole patch series,
including updated versions of loose diffs published earlier. The check
verifies the zip against its published `.sha256`, unpacks the `.diff`/`.patch`
members (ignoring macOS metadata; anything else unexpected stops it for manual
review) and stages them in archive order. Loose diffs of the same CVE are then
superseded: removed here and ignored from then on.

## Decisions for patches that do not apply as-is

Patches are written against the newest (often commercial-only) release of a
line, so they do not always apply to the open-source one. After reviewing a
patch against a specific Qt version, record the outcome in its entry:

```json
"versions": {
  "6.8.5": {
    "action": "skip",
    "reason": "Already fixed in 6.8.5: ...",
    "reviewed": "2026-10-25"
  }
}
```

- `"action": "skip"`: the fix is already there in a different form (or the
  patch is deliberately not used); `reason` explains why.
- `"action": "apply"` with `"min_context": N`: apply with at least N lines of
  matching context (`git apply -CN`, the equivalent of `patch`'s fuzz), for
  context that changed around otherwise identical code.
- `"action": "apply"` with `"recount": true`: for upstream files whose hunk
  headers have wrong line counts.

Decisions are tied to one Qt version, so a new release is checked again from
scratch. A patch that needs a decision and has none fails the build, and every
decision with its reason ends up in the release notes.

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
- follows the reviewed decisions recorded for the Qt version being built
- fails the build if a patch neither applies nor is already present, and has
  no decision

The result of every patch ends up in the release notes.

To drop a patch, remove its file and its `patches.json` entry in the same commit.
