# Qt LGPL
*TLDR*: A repository containing LGPL licensed Qt binaries for the Qt LTS releases, all the commercial bits skipped. Upstream security patches are tracked and applied automatically after review. A simple action to use them in GH workflows is available.

## Motivation

Let's face it: building Qt in all the platforms is a hassle. 

Not only one needs to find the correct set of dependecies to install, divine which of the dozens configure options to use, deal with not so easy to diagnose configuration errors, and then spend a considerable amount of time compiling all the code, but the license for Qt code is (purposefully?) complicated: if you are developing a GPL application you are in luck, all the code in Qt is compatible with that license.

Things gets "interesting" when you want to keep you application's code closed: in this case you are left with paying Qt company for the commercial license (which will give you access to all the modules but taints your code with "developed with Qt commercial" status, this can't be undone) or stick to the LGPL modules; this repository tries to help in this latter case.

You will find here pre-built Qt binaries with ONLY LGPL licensed modules you can use and distribute with your project ; please refer to the [LGPL license](http://www.gnu.org/licenses/lgpl-3.0.html) for all the details.

If you find something missing or not generally correct, feel free to [open an issue](https://github.com/giallu/qt-lgpl/issues/new)

## Supported versions

Only Qt **LTS** lines are built, for Windows (x64), Linux (x64, built on Ubuntu 22.04 for the widest glibc compatibility) and macOS (arm64):

| Line | Status | Notes |
|---|---|---|
| **6.12 LTS** | built | Open-source patch releases are published while 6.12 is new. |
| **6.8 LTS** | built | The newest 6.8 patch releases are commercial-only; their sources become available to open-source users later (6.8.5 was published in October 2026). Upstream security patches are applied on top. |

Modules: qtbase, qtimageformats, qtdeclarative, qtsvg, qtremoteobjects (+ qtactiveqt on Windows). The list lives in [`config/build.json`](config/build.json).

### Security patches

Between releases, Qt publishes fixes for security issues as diff files on download.qt.io. This repository:

1. checks download.qt.io every day for new LTS patch releases and new or changed security patches;
2. verifies every download against the SHA-256 published by download.qt.io;
3. proposes new patches in a pull request, so **nothing reaches a build without a human review**;
4. rebuilds the latest release of the affected line once the patches are merged, bumping the package release number (`6.8.5-1` → `6.8.5-2`).

Every release lists which CVE patches were applied, or were already contained in the upstream release. See [`patches/README.md`](patches/README.md) for the details.

## Qt commercial license
[Qt Group's license terms](https://www.qt.io/terms-conditions/qt-dev-framework) did change (and still do) from time to time, so if you are planning to rely on the Qt library for a commercial activity I suggest you invest in some quality legal advice before choosing Qt and one of the possible licenses.

I am not a lawyer but I've dealt with their license terms long enough so I will try save you some time by summarizing here what I know about it:

1. you need to choose early if you will use the GPL or LGPL license and stick with it. Their license explicitly calls "Prohibited Combination" mixing code developed with (L)GPL and commercial license; this means you can't start with (L)GPL and later acquire the Commercial license to work on the same project (however, I guess if you ask them they will allow it, not sure if and how much that will cost you). This also means you can't have people working on the same project if some of them use the Commercial version: all of them will need a Commercial license.

2. as a corollary to 1, if you started a project with the Commercial license then all of the code you will ever add to it have to come from contributors owning a Commercial license. And someone said GPL was viral...

3. there is a distinction between Application and Devices development when it comes to distribution: software distributed with devices is subject to a royalty.

Summing up: if you are going to create some desktop software based on Qt and you plan to distribute it (for free or for a fee), you can choose to use the LGPL version of Qt you can find here, but be careful to avoid "tainting" the sources with contributions made with Qt Commercial.

## So what can I use these binaries for?

Again, I am not a lawyer so I recommend you consult with a real one if you are going to use Qt for professional purposes.

However, the LGPL license is widespread since ages, so its strenghts and limitations are well known. Summarizing:

1. if you modify and redistribute binaries of the library (out of the scope of my repository, these binaries are compiled from pristine upstream source plus the upstream security patches listed in each release) you need to provide the corresponding source code.
2. if you link statically against LGPL code your work falls under the LGPL as well, so you would need to release the corresponding source code (again out of scope, I only provide here dynamic -aka shared- libraries)
3. if you link dynamically with LGPL code you don't need to release your sources and the resulting combination can be distributed for free or for a fee

## How to use the binaries
Using the binaries is easy: just download the latest version for your OS from the [releases](https://github.com/giallu/qt-lgpl/releases), unpack it anywhere you like the add the `<QT_DIR>/bin` directory to your path so that tools like cmake determine all the other paths automatically.

Each release is tagged `qt-<qt version>-<package release>` (e.g. `qt-6.12.0-1`) and contains one package per OS, e.g. `qt-6.12.0-1-windows2025.zip`, `qt-6.12.0-1-ubuntu2204.tar.xz`, `qt-6.12.0-1-macos15.tar.xz`. Packages carry a build provenance attestation you can check with `gh attestation verify <file> --repo giallu/qt-lgpl`.

For convenience, action is provided in this repo so the setup in a GH workflow is automated by a step like this:

```
- name: Install Qt from giallu/qt-lgpl
  uses: giallu/qt-lgpl@v1
  with:
    qt-version: 6.12.0-1
    os: windows-2025
```

The action verifies the attestation (set `verify-attestation: false` to skip), adds Qt to `PATH` and `CMAKE_PREFIX_PATH`, and exposes the install directory as the `qt-dir` output. Older per-OS releases such as `6.8.1-3` with `os: windows-2019` still work (add `verify-attestation: false` for any that predate attestations).

see [this sample repo](https://github.com/giallu/qt-test-ssl) for a working matrix build example using the action

## Maintaining this repository

- `Build Qt` workflow: run manually with a Qt version (e.g. `6.12.0`) to produce a draft release; it is also started automatically for new patch releases and after security patches are merged.
- `Check upstream Qt` workflow: the daily check described above. It needs *Settings → Actions → General → Allow GitHub Actions to create and approve pull requests* to open patch PRs.
- Tests for the scripts: `python3 -m unittest discover -s tests -v`

## License
All the binaries in this repository are (of course...) LGPL licensed

Everything else is covered by the MIT license

If you need advice just contact me
