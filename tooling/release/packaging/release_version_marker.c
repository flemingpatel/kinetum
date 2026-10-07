// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file release_version_marker.c
 * @brief Exact compiled release-version marker for package-time verification.
 * @author Fleming Patel
 *
 * Every packaged ELF target links this hidden byte string under an explicit
 * linker retention edge. The private package producer checks it against the
 * source VERSION before publication, proving that an archive label cannot
 * diverge from the binaries staged beneath it. The marker is metadata only
 * and exports no ABI symbol.
 */

#ifndef KINETUM_VERSION_STR
#error "KINETUM_VERSION_STR must be supplied by the owning CMake target"
#endif

#if defined(__GNUC__) || defined(__clang__)
__attribute__((used, visibility("hidden")))
#endif
/** Embedded build-version marker inspected when admitting the selected packager image. */
const char kinetum_release_version_marker[] = "KINETUM_RELEASE_VERSION=" KINETUM_VERSION_STR;
