# Third-Party Notices

Kinetum is Apache-2.0 software. This inventory distinguishes source/build
dependencies from bytes redistributed in product packages or the website. It is an
engineering record for the 0.1.0 source tree and does not replace the license
text supplied by any dependency.

## Redistributed Runtime Material

| Component | Relationship | License and package treatment |
|-----------|--------------|-------------------------------|
| DPDK 24.11.7 | Selected static PIC libraries and PMDs are incorporated into the DPDK provider component. | BSD-3-Clause core with files under additional compatible licenses and exceptions. The runtime carries the eight exact upstream license files plus the tuple-derived static-closure attribution from the verified KinetumDPDK package. |

The KinetumDPDK dependency producer also retains Meson 1.12.0's license in the
separate source-build dependency package. Meson bytes are not incorporated into
or shipped with the runtime, SDK, or private validation kit.

## Dynamically Consumed System Dependencies

These components are resolved from the target operating system and are not
copied into Kinetum product archives:

| Component family | Use |
|------------------|-----|
| OpenSSL | SHA-256, Ed25519, and optional TLS. |
| gRPC, Protocol Buffers, and Abseil | RPC transport, generated wire types, protobuf runtime, and synchronization utilities. |
| elfutils `libelf` | Cold ELF inspection during provider admission. |
| libarchive | Native archive I/O in `kinetum_package` only; no runtime, SDK-interface, module, or provider link edge. |
| zlib | Checked gzip decoding in `kinetum_package`; its direct build/link dependency is private to that executable. |
| libnuma, POSIX threads, `libdl`, `libm`, and `librt` | System prerequisites of the exact DPDK/native closure. |
| C and C++ runtimes | Language and operating-system runtime support. |

The final two-tuple release gate inspects each ELF `DT_NEEDED` closure. A
target package manager remains responsible for the licenses and updates of
these system-provided libraries.

The fixed KinetumDPDK builder also uses the Ubuntu libfdt and libpcap
development packages to reproduce its generated DPDK configuration. Their
libraries are not linked into the selected provider closure and do not enter a
Kinetum product archive.

## Documentation Website Assets

The generated documentation website redistributes static Sphinx, Pygments
syntax-highlighting, Read the Docs theme, jQuery 3.6.0 in the narrative site,
jQuery 3.6.0 in the Doxygen API site, Font Awesome, Lato, Roboto Slab, and
Doxygen output assets. Their complete notices travel with the website
under `_licenses/` from
`third_party/documentation/licenses/`. Kinetum's Apache-2.0 license is copied
there for the Roboto Slab and Kinetum asset terms that refer to it.

Sphinx 8.1.3, Pygments 2.21.0, MyST-Parser 4.0.1,
sphinx-rtd-theme 3.1.0, sphinxcontrib-plantuml 0.31, PlantUML 1.2026.8,
Java 21, Graphviz 2.43.0, and Doxygen 1.9.8 are build tools. Except for the
static assets named above, their program and package bytes are not copied into
the website. PlantUML output is static SVG.

## Validation and Test Dependencies

GoogleTest, Clang analysis tools, strace, pytest, pytest-subtests, Python lint tools,
pyelftools, Matplotlib, tcpdump, iproute2, OpenSSH, and TRex are build, test, report,
or external-lab tools.
Kinetum product archives do not embed their program bytes. The private validation
wheel carries Kinetum-authored code, resources, and native helpers. Pip installs
its Python dependencies separately; system and traffic tools remain host
prerequisites. Python build, Hatchling, pip-tools, setuptools, and wheel are packaging tools
and are not included in the private wheel. The development and documentation
Python environments use `tooling/environment/requirements.lock`.

## Package Projection

- The runtime package receives Kinetum `LICENSE`, `NOTICE`, its runtime-specific
  notice, the exact verified DPDK license tree, and the generated static-closure
  copyright attribution.
- The SDK package receives Kinetum `LICENSE` and `NOTICE`. Its current headers,
  examples, build metadata, and native installer carry no copied website assets;
  dynamically consumed system dependencies remain the operating system's packages.
- The separately published documentation website carries its complete
  `_licenses/` tree with the static assets that require those notices.
- The private validation kit receives Kinetum `LICENSE`, `NOTICE`, and its
  kit-specific notice. No DPDK or documentation-asset license is copied merely
  because validation can invoke the runtime.
- The source-build KinetumDPDK package continues to retain exact DPDK and Meson
  upstream license files through its own producer.

License compatibility and notice completeness require final counsel review
before a public release.
