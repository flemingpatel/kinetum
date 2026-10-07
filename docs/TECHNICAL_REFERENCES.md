# Technical References

This page is the single external-reference index for Kinetum's public
documentation. It records specifications that define implemented contracts and
primary technical work that explains an algorithm or a deliberately considered
alternative. A citation acknowledges a technical relationship; it does not
imply affiliation, endorsement, or copied implementation.

Kinetum documentation paraphrases these sources and contains no copied diagram
or extended passage. Dependency licenses and redistribution notices are a
separate concern documented in the root `THIRD_PARTY_NOTICES.md`.

## Table of Contents

1. [Normative External Specifications](#normative-external-specifications)
2. [Technical Background](#technical-background)
3. [Maintenance Rule](#maintenance-rule)

---

## Normative External Specifications

| Specification | Owner | Relevance to Kinetum |
|---------------|-------|----------------------|
| [ISO/IEC 9899:2011 draft N1570](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf) | ISO C working group WG14 | Defines the C11 language and object model used by the public module and provider ABI headers. |
| [ISO C++20 working draft N4861](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2020/n4861.pdf) | ISO C++ working group WG21 | Defines the C++20 language, layout, atomics, and memory-order semantics used by the implementation. The release compiler remains the executable conformance authority. |
| [RFC 8259, The JavaScript Object Notation Data Interchange Format](https://www.rfc-editor.org/rfc/rfc8259) | IETF | Defines the JSON grammar consumed by built-in module configuration and strict validation artifact readers. Kinetum additionally rejects duplicate members and noncanonical scalar forms at its owning boundaries. |
| [RFC 3339, Date and Time on the Internet: Timestamps](https://www.rfc-editor.org/rfc/rfc3339) | IETF | Defines the timestamp syntax used by platform diagnostics. Kinetum uses UTC with six fractional digits inside its fixed readable text format. |
| [RFC 791, Internet Protocol](https://www.rfc-editor.org/rfc/rfc791), [RFC 768, User Datagram Protocol](https://www.rfc-editor.org/rfc/rfc768), and [RFC 9293, Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc9293) | IETF | Define the IPv4, UDP, and TCP wire fields consumed by Kinetum's header-owned big-endian readers and packet parser. |
| [Protocol Buffers language guide](https://protobuf.dev/programming-guides/proto3/) and [encoding](https://protobuf.dev/programming-guides/encoding/) | Protocol Buffers project | Defines proto3 presence and wire encoding. Kinetum adds stricter recursive unknown-field, enum, canonicalization, and identity rules. |
| [gRPC status codes](https://grpc.io/docs/guides/status-codes/) | gRPC project | Defines transport status categories. Kinetum separately validates application status carried inside successful transports. |
| [System V ABI, generic ELF ABI](https://gabi.xinuos.com/elf/) | System V ABI maintainers | Defines the ELF structures inspected during provider-component and module-image admission. |
| [GNU linker options](https://sourceware.org/binutils/docs/ld/Options.html) | GNU Binutils project | Defines the visibility, version-script, no-undefined, RELRO, and archive-link controls used by image policy. |
| [GCC x86 CPU options](https://gcc.gnu.org/onlinedocs/gcc-13.3.0/gcc/x86-Options.html), [GCC AArch64 CPU options](https://gcc.gnu.org/onlinedocs/gcc-13.3.0/gcc/AArch64-Options.html), and [Clang target options](https://releases.llvm.org/18.1.8/tools/clang/docs/ClangCommandLineReference.html#target-dependent-compilation-options) | GNU and LLVM compiler projects | Define native CPU selection, explicit instruction-set baselines, and compiler feature availability. Kinetum selects CPU flags privately for owned Release targets; package integrity and CPU/performance qualification remain distinct contracts. |
| [Linux `openat(2)`](https://man7.org/linux/man-pages/man2/openat.2.html), [`renameat2(2)`](https://man7.org/linux/man-pages/man2/rename.2.html), [`proc_pid_exe(5)`](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html), [`sched_setaffinity(2)`](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html), [`signalfd(2)`](https://man7.org/linux/man-pages/man2/signalfd.2.html), and [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html) | Linux man-pages project | Defines descriptor-rooted path operations, atomic directory exchange, process-image identity, CPU placement, signal ownership, and wake-only event descriptors used by the Linux runtime and documentation producer. |
| [Linux memory barriers](https://docs.kernel.org/core-api/wrappers/memory-barriers.html) and [RCU concepts](https://docs.kernel.org/RCU/whatisRCU.html) | Linux kernel project | Primary platform guidance for publication ordering and read-copy-update terminology. C++ memory-order rules remain the language authority. |
| [Linux HugeTLB pages](https://docs.kernel.org/admin-guide/mm/hugetlbpage.html) | Linux kernel project | Defines the host hugepage mechanism consumed by DPDK-backed deployments. |
| [DPDK 24.11 Programmer's Guide](https://doc.dpdk.org/guides-24.11/prog_guide/index.html) and [NIC feature contracts](https://doc.dpdk.org/guides-24.11/nics/features.html#fast-mbuf-free) | DPDK project | Define the EAL, PMD, mempool, ring, queue, and hugepage mechanisms used inside the DPDK provider. The fast-free contract restricts a TX queue to one mempool; multi-domain TX admission excludes that mode. |
| [OpenSSL EVP signature API](https://docs.openssl.org/3.0/man7/EVP_SIGNATURE-ED25519/) | OpenSSL project | Defines the Ed25519 signing and verification API used for installed provider inventory authenticity. |
| [FIPS PUB 180-4, Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) | NIST | Defines SHA-256, the content-identity primitive used for plans, snapshots, manifests, and artifacts. |
| [RFC 8032, Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032) | IETF | Defines Ed25519 behavior used by provider inventory signatures. |
| [SPDX specification](https://spdx.github.io/spdx-spec/v2.3/) | SPDX project | Defines the per-file license identifiers used by Kinetum-authored compiled-language sources. |
| [Python project metadata](https://packaging.python.org/en/latest/specifications/pyproject-toml/) and [wheel format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/) | Python Packaging Authority | Define dependency declarations, native platform tags, and installation layout for the private validation wheel. |

## Technical Background

| Work | Author or owner | Relevance to Kinetum |
|------|-----------------|----------------------|
| [RFC 1624, Computation of the Internet Checksum via Incremental Update](https://www.rfc-editor.org/rfc/rfc1624) | IETF | Supplies the changed-word arithmetic used by NAT44 and the header-owned checksum helper, including the positive-zero boundary. |
| ["Distributed Snapshots: Determining Global States of Distributed Systems"](https://doi.org/10.1145/214451.214456) | K. Mani Chandy and Leslie Lamport, 1985 | Provides the consistent-cut vocabulary used to reason about DATA and control-channel ordering. Kinetum's sequence CUT is a local boundary protocol, not an implementation of the paper's distributed snapshot algorithm. |
| ["Abstractions for Network Update"](https://doi.org/10.1145/2342356.2342427) | Mark Reitblatt, Nate Foster, Jennifer Rexford, Cole Schlesinger, and David Walker, 2012 | Defines per-packet consistent network updates through versioned rules. The ordered-CUT guide compares that valid dual-version model with Kinetum's epoch-exclusive owner handoff. |
| ["Lightweight Asynchronous Snapshots for Distributed Dataflows"](https://arxiv.org/abs/1506.08603) | Paris Carbone, Gyula Fora, Stephan Ewen, Seif Haridi, and Kostas Tzoumas, 2015 | Explains aligned barriers across streaming inputs; Kinetum's fan-in proof similarly requires every exact input cut before local activation. |
| ["Read-Copy Update: Using Execution History to Solve Concurrency Problems"](https://www.rdrop.com/users/paulmck/RCU/RCU.1998.06.12.pdf) | Paul E. McKenney and John D. Slingwine, 1998 | Background for single-writer publication and reader grace. Kinetum also uses an exact-generation QSBR domain with its own stricter adjacency rules. |
| ["Foundations of the C++ Concurrency Memory Model"](https://doi.org/10.1145/1375581.1375591) | Hans-J. Boehm and Sarita V. Adve, 2008 | Grounds the acquire/release and data-race-free reasoning used by Kinetum's lock-free publications. |
| ["What Every Programmer Should Know About Memory"](https://people.freebsd.org/~lstewart/articles/cpumemory.pdf) | Ulrich Drepper, 2007 | Background for cache-line ownership, false sharing, NUMA placement, and TLB behavior. Target qualification supplies measured platform evidence. |
| ["Cuckoo Hashing"](https://doi.org/10.1016/j.jalgor.2003.12.002) | Rasmus Pagh and Flemming Friche Rodler, 2004 | Defines the two-location cuckoo-hashing model used by the bounded lookup primitive. |
| ["MemC3: Compact and Concurrent MemCache with Dumber Caching and Smarter Hashing"](https://www.usenix.org/conference/nsdi13/technical-sessions/presentation/fan) | Bin Fan, David G. Andersen, and Michael Kaminsky, 2013 | Provides cache-aware cuckoo-hashing background relevant to bucket layout and bounded probes. |
| ["Hashed and Hierarchical Timing Wheels"](https://doi.org/10.1145/41457.37504) | George Varghese and Tony Lauck, 1987 | Defines the timer-wheel organization used by the shared active-stage timer primitive. |
| [VPP architecture](https://s3-docs.fd.io/vpp/25.06/aboutvpp/technology.html) and [CPU target selection](https://github.com/FDio/vpp/blob/stable/2510/src/cmake/cpu.cmake) | FD.io VPP project | Background for vector packet processing, batch-oriented graph dispatch, explicit CPU baselines, and selectively compiled instruction-set variants. Kinetum uses its own SoA and ownership contracts and retains compile-time SIMD selection. |
| [DPDK native and generic build targets](https://doc.dpdk.org/guides-24.11/linux_gsg/build_dpdk.html#adjusting-build-options) | DPDK project | Distinguishes machine-specific, architecture-baseline, and SoC-specific builds. Kinetum's dependency producer retains its independent exact tuple policy; packaging a selected build does not establish its public-release qualification. |

## Maintenance Rule

Add a reference only when current source or a current design comparison depends
on it. Prefer a standards body, project manual, DOI, author publication page, or
other primary source. Do not add generic reading lists, product marketing,
copied prose, or a name without a stated technical relationship.
