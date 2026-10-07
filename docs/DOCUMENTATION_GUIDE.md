# Documentation Guide

Build, preview, and publish the guides and C/C++ API reference from the source
tree. The website is independent of runtime and SDK packages.

## Table of Contents

**Part 1: Build and Preview**

1. [Prepare the Host](#1-prepare-the-host)
2. [Build the Website](#2-build-the-website)
3. [Preview](#3-preview)

**Part 2: Maintenance and Publication**

4. [Source Files](#4-source-files)
5. [Verify the Site](#5-verify-the-site)
6. [Publish](#6-publish)

---

## Part 1: Build and Preview

### 1. Prepare the Host

Use an Ubuntu 24.04 x86-64 or AArch64 host. From the source root, run the
project bootstrap:

```bash
sudo ./tooling/environment/bootstrap_ubuntu.sh
```

Bootstrap supplies Python 3.12, the locked Python packages, Doxygen 1.9.8,
Java 21, Graphviz, and DejaVu fonts alongside the platform development dependencies.

### 2. Build the Website

From the source root, as your normal user:

```bash
./tooling/release/documentation/build_documentation.py
```

The completed site is `build/docs/html/`. The producer prepares and validates
locked Python packages and the pinned PlantUML JAR in `build/docs/tools/`.
The first build needs network access; later builds reuse unchanged cached tools.
No platform build or CMake configuration is required by the website producer.

Run the same command after edits. To select another output directory, pass
`--output-root /absolute/directory`; its parent must exist, and the site is
published under its `html/` child.

### 3. Preview

Serve the generated site on the build host:

```bash
python3 -B -m http.server 8000 --bind 127.0.0.1 --directory build/docs/html
```

Open `http://127.0.0.1:8000`. For a remote build host, forward the port from your
workstation, replacing `user@build-host` with your SSH destination:

```bash
ssh -N -L 8000:127.0.0.1:8000 user@build-host
```

Open the same address locally and keep both commands running while viewing.

## Part 2: Maintenance and Publication

### 4. Source Files

| Content | Source |
|---------|--------|
| Guides | Markdown under `docs/`, `src/modules/README.md`, and `CHANGELOG.md`. |
| Navigation | Links in `docs/README.md`; the producer derives Sphinx's toctree from them. |
| C/C++ API | Installed public headers under `include/kinetum/`, rendered by Doxygen. |
| Diagrams | `{uml}` fenced directives in Markdown, rendered to static SVG with PlantUML's default style. |
| Rendering tools | `tooling/environment/requirements.lock` and producer version/digest pins. |

Keep generated HTML, doctrees, tool caches, and screenshots
out of source control. Tool environments stay at their original cache paths.
Readers need only the published site, including its local assets and notices.

### 5. Verify the Site

Check the completed site against current sources before publishing:

```bash
./tooling/release/documentation/build_documentation.py --verify-only
```

Check external links when network access is available:

```bash
./tooling/release/documentation/build_documentation.py --check-links
```

The producer rejects malformed diagrams, unresolved references, missing or
external page assets, path leakage, and source or output drift. Its manifest
checks build staleness and integrity; it is not builder attestation. Review
tables, diagrams, navigation, and API pages at desktop and narrow widths.

### 6. Publish

Publish the complete verified `build/docs/html/` tree to the static host,
including `_licenses/`. Do not publish staging directories or tool caches.

The Linux producer serializes builds per output directory, bounds child-tool
lifetimes, validates a complete candidate, and atomically replaces `html/`.
Post-publication validation failure restores the previous validated site.
Runtime and SDK packaging do not build or consume the website.
