# Kinetum Runtime Third-Party Notices

The Kinetum runtime statically incorporates selected DPDK 24.11.7 libraries and
PMDs into its DPDK provider component. DPDK's complete license set for the
verified source package is installed at:

`share/licenses/KinetumDPDK/dpdk/`

That directory contains the exact upstream `README`, BSD-2-Clause,
BSD-3-Clause, exception, GPL-2.0, ISC, LGPL-2.1, and MIT files retained by the
source-produced KinetumDPDK package.

Copyright statements derived from the exact static archive object/header graph
are installed at:

`share/licenses/KinetumDPDK/DPDK_STATIC_CLOSURE_NOTICE.txt`

OpenSSL, gRPC, Protocol Buffers, Abseil, elfutils `libelf`, libarchive, zlib,
libnuma, the C/C++ runtimes, and ordinary operating-system prerequisites are
dynamically consumed from the target system and are not copied into this
runtime archive.
