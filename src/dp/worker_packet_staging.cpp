// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * @file worker_packet_staging.cpp
 * @brief Checked construction and teardown of all packet roles in one worker NUMA mapping.
 * @author Fleming Patel
 */

#include "src/dp/worker_packet_staging.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <limits>
#include <new>
#include <stdexcept>
#include <vector>

#include "src/common/status.hpp"

namespace kinetum::dp
{
namespace
{

/** @brief Proven offsets for one role's controls and key-major pointer arrays. */
struct role_layout {
	std::size_t state{0u};		 ///< Role controls in the shared mapping.
	std::size_t keys{0u};		 ///< Per-key queue controls and claimed flags.
	std::size_t ready{0u};		 ///< Ready-key FIFO element storage.
	std::size_t ready_capacity{0u};	 ///< Physical ready extent; zero only when no keys exist.
	std::size_t pointers{0u};	 ///< First key's pointer storage, after the entire control area.
	std::size_t pointer_stride{0u};	 ///< Cache-line-aligned byte extent for each key.
};

/** @brief Checked cold layout for one domain and its active/optional future roles. */
struct domain_layout {
	std::size_t identities{0u};	     ///< Immutable key identities shared across roles.
	std::array<role_layout, 2> roles{};  ///< Active role followed by future when authored.
	std::size_t role_count{0u};	     ///< One or two physical role sets.
};

/** @param key Cold candidate identity. @return Whether its stage, phase and padding are valid. */
[[nodiscard]] bool valid_key(const packet_work_key &key) noexcept
{
	if (key.stage_instance_index >= INVALID_STAGE_ID ||
	    std::any_of(key.padding.begin(), key.padding.end(), [](uint8_t byte) { return byte != 0u; })) {
		return false;
	}
	switch (key.phase) {
	case packet_work_phase::RX_DELIVER:
	case packet_work_phase::EXECUTE:
	case packet_work_phase::STAGE_DELIVER:
	case packet_work_phase::BOUNDARY_SEND:
	case packet_work_phase::TX_DELIVER:
		return true;
	}
	return false;
}

}  // namespace

common::status_or<std::unique_ptr<worker_packet_staging>>
worker_packet_staging::create(std::span<const worker_packet_staging_domain> domains, int32_t numa_node)
{
	using domain_type = packet_epoch_input_staging;
	using role_type = domain_type::role_state;
	using key_type = domain_type::key_state;
	using pointer_storage = domain_type::packet_queue::storage_type;
	using ready_storage = domain_type::ready_queue::storage_type;
	constexpr std::size_t ALIGNMENT = algo::CACHE_LINE_SIZE;
	static_assert(alignof(domain_type) == ALIGNMENT && alignof(role_type) == ALIGNMENT);
	static_assert(alignof(key_type) <= ALIGNMENT && alignof(pointer_storage) <= ALIGNMENT);
	if (numa_node < 0 || domains.size() >= UINT32_MAX) {
		return common::status::invalid_argument(
			"packet staging requires exact NUMA and compact domain identities");
	}
	for (std::size_t index = 0u; index < domains.size(); ++index) {
		const auto &domain = domains[index];
		if (domain.storage_domain_index == UINT32_MAX ||
		    (index != 0u && domains[index - 1u].storage_domain_index >= domain.storage_domain_index) ||
		    !domain_type::packet_queue::valid_capacity(domain.capacity) || domain.keys.size() >= UINT32_MAX ||
		    (domain.future_capacity.has_value() && domain.future_capacity.value() != domain.capacity)) {
			return common::status::invalid_argument(
				"packet staging domains require sorted identities and exact role capacities");
		}
		for (std::size_t key = 0u; key < domain.keys.size(); ++key) {
			if (!valid_key(domain.keys[key]) ||
			    (key != 0u && !(domain.keys[key - 1u] < domain.keys[key]))) {
				return common::status::invalid_argument(
					"packet staging keys must be valid, sorted and unique");
			}
		}
	}

	std::vector<domain_layout> layouts;
	try {
		layouts.resize(domains.size());
	} catch (const std::bad_alloc &) {
		return common::status::resource_exhausted("packet staging layout allocation failed");
	} catch (const std::length_error &) {
		return common::status(common::status_code::OUT_OF_RANGE, "packet staging layout exceeds host size");
	}
	numa_layout allocation;
	std::size_t domains_offset = 0u;
	const auto overflow = [] {
		return common::status(common::status_code::OUT_OF_RANGE, "packet staging storage extent overflows");
	};
	if (!allocation.append<domain_type>(domains.size(), domains_offset, ALIGNMENT)) {
		return overflow();
	}
	for (std::size_t index = 0u; index < domains.size(); ++index) {
		const auto &domain = domains[index];
		auto &layout = layouts[index];
		layout.role_count = domain.future_capacity.has_value() ? 2u : 1u;
		if (!allocation.append<packet_work_key>(domain.keys.size(), layout.identities)) {
			return overflow();
		}
		for (std::size_t role = 0u; role < layout.role_count; ++role) {
			auto &row = layout.roles[role];
			row.ready_capacity =
				domain.keys.empty() ? 0u : std::bit_ceil(std::max<std::size_t>(2u, domain.keys.size()));
			if ((!domain.keys.empty() && !domain_type::ready_queue::valid_capacity(row.ready_capacity)) ||
			    !allocation.append<role_type>(1u, row.state, ALIGNMENT) ||
			    !allocation.append<key_type>(domain.keys.size(), row.keys) ||
			    !allocation.append<ready_storage>(row.ready_capacity, row.ready)) {
				return overflow();
			}
		}
	}
	// All mutable controls precede every pointer array. Each key gets one
	// contiguous capacity-C extent; neither padding nor other keys grant credit.
	for (std::size_t index = 0u; index < domains.size(); ++index) {
		const auto &domain = domains[index];
		for (std::size_t role = 0u; role < layouts[index].role_count; ++role) {
			auto &row = layouts[index].roles[role];
			if (domain.keys.empty()) {
				continue;
			}
			if (!allocation.append_rows<pointer_storage>(domain.keys.size(), domain.capacity, row.pointers,
								     row.pointer_stride, ALIGNMENT)) {
				return overflow();
			}
		}
	}

	std::unique_ptr<worker_packet_staging> owner(new (std::nothrow) worker_packet_staging());
	if (owner == nullptr) {
		return common::status::resource_exhausted("packet staging owner allocation failed");
	}
	if (domains.empty()) {
		return owner;
	}
	auto storage_or = allocation.allocate(numa_node);
	if (!storage_or.is_ok()) {
		return storage_or.error();
	}
	owner->storage_ = std::move(storage_or).value();
	auto domain_states = numa_layout::storage<domain_type>(owner->storage_, domains_offset, domains.size());
	// Every constructor below is nonthrowing and consumes only proved extents.
	// Publish each complete empty domain before proceeding to the next one.
	for (std::size_t index = 0u; index < domains.size(); ++index) {
		const auto &domain = domains[index];
		const auto &layout = layouts[index];
		auto identities =
			numa_layout::storage<packet_work_key>(owner->storage_, layout.identities, domain.keys.size());
		for (std::size_t key = 0u; key < domain.keys.size(); ++key) {
			std::construct_at(&identities[key], domain.keys[key]);
		}
		std::array<role_type *, 2> roles{};
		for (std::size_t role = 0u; role < layout.role_count; ++role) {
			const auto &row = layout.roles[role];
			auto keys = numa_layout::storage<key_type>(owner->storage_, row.keys, domain.keys.size());
			for (std::size_t key = 0u; key < domain.keys.size(); ++key) {
				auto pointers = numa_layout::row<pointer_storage>(owner->storage_, row.pointers,
										  row.pointer_stride, key,
										  domain.keys.size(), domain.capacity);
				std::construct_at(&keys[key], pointers.data(), domain.capacity);
			}
			auto ready =
				numa_layout::storage<ready_storage>(owner->storage_, row.ready, row.ready_capacity);
			roles[role] =
				std::construct_at(numa_layout::storage<role_type>(owner->storage_, row.state).data(),
						  keys, domain.capacity, ready.data(), row.ready_capacity);
		}
		new (&domain_states[index])
			domain_type(domain.storage_domain_index, numa_node, identities, roles[0], roles[1]);
		owner->domains_ = domain_states.first(index + 1u);
	}
	return owner;
}

worker_packet_staging::~worker_packet_staging()
{
	// Preflight every role before destroying any borrowed state or backing page.
	for (const auto &domain : domains_) {
		if (!domain.empty()) {
			std::terminate();
		}
		for (const auto *role : domain.physical_roles_) {
			if (role == nullptr) {
				continue;
			}
			for (const auto &key : role->keys) {
				if (key.claimed || !key.queue.empty()) {
					std::terminate();
				}
			}
		}
	}
	for (std::size_t index = domains_.size(); index != 0u; --index) {
		auto &domain = domains_[index - 1u];
		for (std::size_t role_index = domain.physical_roles_.size(); role_index != 0u; --role_index) {
			auto *role = domain.physical_roles_[role_index - 1u];
			if (role == nullptr) {
				continue;
			}
			const auto keys = role->keys;
			std::destroy_at(role);
			for (std::size_t key = keys.size(); key != 0u; --key) {
				std::destroy_at(&keys[key - 1u]);
			}
		}
		std::destroy_at(&domain);
	}
}

}  // namespace kinetum::dp
