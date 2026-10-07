// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file dpdk_native_visibility.hpp
 * @brief Component-private ownership declaration for DPDK fast-path state.
 * @author Fleming Patel
 *
 * The hermetic DPDK producer compiles the one archive-owned definition of
 * `rte_eth_fp_ops` with hidden visibility. Every Kinetum translation unit that
 * expands DPDK's inline RX/TX burst accessors must see the matching hidden
 * declaration. This two-sided ELF contract permits direct-address relaxation
 * on both supported architectures and prevents a GOT/interposition path to
 * state that is owned entirely by one component or native-test process.
 */

#include <rte_ethdev.h>
#include <rte_ethdev_core.h>

#if !defined(__GNUC__) && !defined(__clang__)
#error "Kinetum DPDK native visibility requires a GNU-compatible compiler"
#endif

/**
 * Component/process-local DPDK ethdev fast-path operation state.
 *
 * DPDK declares this object with C++ linkage when included from C++. This
 * matching redeclaration changes only ELF visibility.
 */
extern struct rte_eth_fp_ops rte_eth_fp_ops[RTE_MAX_ETHPORTS] __attribute__((visibility("hidden")));
