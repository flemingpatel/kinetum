// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file cuckoo.hpp
 * @brief Cuckoo hash table with O(1) worst-case lookup.
 * @author Fleming Patel
 *
 * Cuckoo hashing provides constant-time lookups in the worst case by using
 * two derived bucket candidates and allowing elements to be displaced during insertion.
 *
 * Key Properties:
 * - O(1) expected insertion (amortized)
 * - Lookup checks at most two candidate buckets
 * - Cache-line-aligned bucket starts for predictable memory access
 *
 * Thread Safety:
 * - Lookups are lock-free (read-only)
 * - Insertions/deletions require external synchronization
 * - Concurrent mutation requires external serialization; packet paths use
 *   owner-local maps rather than a shared lock
 *
 * Algorithm background is maintained in `docs/TECHNICAL_REFERENCES.md`.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory_resource>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

#include <kinetum/algo/bits.hpp>
#include <kinetum/algo/hash.hpp>
#include <kinetum/algo/platform.hpp>
#include <kinetum/algo/prefetch.hpp>

namespace kinetum::algo
{

// =============================================================================
// Constants
// =============================================================================

/** Maximum bounded displacement attempts before insertion rejects. */
inline constexpr std::size_t CUCKOO_MAX_KICKS = 500;

/** Fixed entry count per cache-line-aligned bucket. */
inline constexpr std::size_t CUCKOO_BUCKET_SIZE = 4;

// =============================================================================
// Cuckoo Bucket
// =============================================================================

/**
 * @brief Single bucket containing multiple entries.
 *
 * Using buckets of four entries improves locality and reduces displacement
 * chains. Every bucket starts on a cache-line boundary; its complete extent
 * depends on the caller's key and value types and may span multiple lines.
 *
 * @tparam Key Default-constructible, trivially copyable key with non-throwing
 *         copy assignment and equality.
 * @tparam Value Default-constructible value with non-throwing copy assignment.
 */
template <typename Key, typename Value>
struct alignas(CACHE_LINE_SIZE) cuckoo_bucket {
	static_assert(std::is_trivially_copyable_v<Key>,
		      "Key must be trivially copyable for cache efficiency. "
		      "Use std::unordered_map for non-trivially-copyable keys (cold path).");
	static_assert(std::is_default_constructible_v<Key> && std::is_default_constructible_v<Value>,
		      "Cuckoo bucket entries require default-constructible key and value types");
	static_assert(std::is_nothrow_copy_assignable_v<Key> && std::is_nothrow_copy_assignable_v<Value>,
		      "Cuckoo bucket mutation requires nothrow copy assignment");
	static_assert(noexcept(std::declval<const Key &>() == std::declval<const Key &>()),
		      "Cuckoo lookup requires nothrow key equality");

	/** @brief One default-constructed entry with explicit occupancy state. */
	struct entry {
		Key key{};	       ///< Exact semantic lookup key.
		Value value{};	       ///< Value owned while @p occupied is true.
		bool occupied{false};  ///< Whether this entry currently owns a key/value pair.
		uint8_t _pad[7]{};     ///< Explicit occupancy padding; key/value types determine entry alignment.
	};

	std::array<entry, CUCKOO_BUCKET_SIZE> entries{};  ///< Fixed bucket entry extent.

	/**
	 * @brief Find entry in bucket.
	 * @param key Key to find
	 * @return Pointer to value if found, nullptr otherwise
	 */
	KINETUM_ALWAYS_INLINE
	Value *find(const Key &key) noexcept
	{
		for (auto &e : entries) {
			if (e.occupied && e.key == key) {
				return &e.value;
			}
		}
		return nullptr;
	}

	/**
	 * @brief Find an immutable value in this bucket.
	 * @param key Key to find.
	 * @return Immutable value pointer, or nullptr when absent.
	 */
	KINETUM_ALWAYS_INLINE
	const Value *find(const Key &key) const noexcept
	{
		for (const auto &e : entries) {
			if (e.occupied && e.key == key) {
				return &e.value;
			}
		}
		return nullptr;
	}

	/**
	 * @brief Try to insert entry into bucket.
	 * @param key Key to insert
	 * @param value Value to insert
	 * @return true if inserted, false if bucket is full
	 */
	KINETUM_ALWAYS_INLINE
	bool try_insert(const Key &key, const Value &value) noexcept
	{
		for (auto &e : entries) {
			if (!e.occupied) {
				e.key = key;
				e.value = value;
				e.occupied = true;
				return true;
			}
		}
		return false;
	}

	/**
	 * @brief Remove entry from bucket.
	 * @param key Key to remove
	 * @return true if removed, false if not found
	 */
	KINETUM_ALWAYS_INLINE
	bool remove(const Key &key) noexcept
	{
		for (auto &e : entries) {
			if (e.occupied && e.key == key) {
				e.occupied = false;
				return true;
			}
		}
		return false;
	}
};

// =============================================================================
// Cuckoo Hash Table
// =============================================================================

/**
 * @brief Fixed-capacity cuckoo hash table.
 *
 * Provides O(1) worst-case lookup by checking at most two candidate buckets.
 * Uses bucketing (4 entries per bucket) to improve cache efficiency and
 * reduce the frequency of displacements.
 *
 * @tparam Key Default-constructible, trivially copyable key with non-throwing
 *         copy and equality.
 * @tparam Value Default-constructible value with non-throwing copy operations.
 * @tparam Hash Non-throwing field-wise hash function.
 *
 * Example:
 * @code
 * struct flow_key { uint32_t src_ip, dst_ip; uint16_t src_port, dst_port; uint8_t proto; };
 * struct flow_key_hash {
 *     std::size_t operator()(const flow_key& key) const noexcept {
 *         uint64_t hash = FNV1A_OFFSET_BASIS;
 *         const auto mix = [&hash](uint64_t field) noexcept {
 *             for (uint32_t shift = 0; shift < 64; shift += 8) {
 *                 hash ^= static_cast<uint8_t>(field >> shift);
 *                 hash *= FNV1A_PRIME;
 *             }
 *         };
 *         mix(key.src_ip); mix(key.dst_ip); mix(key.src_port);
 *         mix(key.dst_port); mix(key.proto);
 *         return static_cast<std::size_t>(hash);
 *     }
 * };
 * std::pmr::monotonic_buffer_resource memory;
 * cuckoo_map<flow_key, session_state, flow_key_hash> sessions(1024, &memory);
 *
 * flow_key key{...};
 * sessions.insert(key, session_state{...});
 *
 * if (auto* session = sessions.find(key)) {
 *     // O(1) worst-case lookup!
 * }
 * @endcode
 */
template <typename Key, typename Value, typename Hash>
class cuckoo_map {
	static_assert(std::is_nothrow_copy_constructible_v<Key> && std::is_nothrow_copy_assignable_v<Key>,
		      "cuckoo_map requires nothrow-copyable keys for failure-atomic insertion");
	static_assert(std::is_nothrow_copy_constructible_v<Value> && std::is_nothrow_copy_assignable_v<Value>,
		      "cuckoo_map requires nothrow-copyable values for failure-atomic insertion");
	static_assert(std::is_nothrow_invocable_r_v<std::size_t, const Hash &, const Key &>,
		      "cuckoo_map requires a nothrow hash function on the lookup path");
	static_assert(noexcept(std::declval<const Key &>() == std::declval<const Key &>()),
		      "cuckoo_map requires nothrow key equality on the lookup path");

    public:
	using size_type = std::size_t;	///< Public size and bucket-count type.

	/**
	 * @brief Copied key and bucket coordinates issued by one stable map.
	 *
	 * The map must outlive this value. No entry, value or lookup result is
	 * borrowed: intervening mutations are observed by find(). Only the map
	 * can construct a query; copying preserves its issuing identity.
	 */
	class prepared_query {
	    public:
		/** @brief Copy one complete query without moving its key. */
		prepared_query(const prepared_query &) noexcept = default;
		/** @brief Replace this query with one complete copied query. @return This destination. */
		prepared_query &operator=(const prepared_query &) noexcept = default;

		/** @return The immutable semantic key owned by this query. */
		[[nodiscard]] const Key &key() const noexcept
		{
			return key_;
		}

	    private:
		friend class cuckoo_map;

		/**
		 * @brief Bind a copied key to its issuing map and exact bucket ordinals.
		 * @param owner Stable map that issued these coordinates.
		 * @param key Semantic identity copied without default construction or moving.
		 * @param first First-table bucket ordinal.
		 * @param second Second-table bucket ordinal.
		 */
		prepared_query(const cuckoo_map *owner, const Key &key, size_type first, size_type second) noexcept
			: owner_(owner)
			, key_(key)
			, first_(first)
			, second_(second)
		{
		}

		const cuckoo_map *owner_;  ///< Stable issuing-map identity; never an entry borrow.
		Key key_;		   ///< Semantic key, copied through the map's nothrow contract.
		size_type first_;	   ///< First-table bucket ordinal.
		size_type second_;	   ///< Second-table bucket ordinal.
	};

	/**
	 * @brief Construct cuckoo map with specified capacity.
	 *
	 * @param num_buckets Positive bucket count, rounded to the next power of two.
	 * @param memory_resource Cold-path storage authority for both tables and
	 *        the failure-atomic displacement log; it must outlive the map.
	 * @throws std::invalid_argument when the bucket count is zero or cannot be
	 *         rounded without overflow, or when @p memory_resource is null.
	 * @throws Exceptions from the supplied resource or cold key/value/hash construction.
	 *
	 * @note Actual capacity is num_buckets * CUCKOO_BUCKET_SIZE * 2 (two tables)
	 * @note Recommended load factor: 50% for best performance
	 */
	explicit cuckoo_map(size_type num_buckets, std::pmr::memory_resource *memory_resource)
		: num_buckets_(normalize_bucket_count_(num_buckets))
		, mask_(num_buckets_ - 1)
		, table1_(num_buckets_, require_memory_resource_(memory_resource))
		, table2_(num_buckets_, require_memory_resource_(memory_resource))
		, undo_log_(CUCKOO_MAX_KICKS, require_memory_resource_(memory_resource))
	{
	}

	/** @brief Preserve the exact resource and issuing-map identity. */
	cuckoo_map(const cuckoo_map &) = delete;
	/** @brief Preserve the exact resource and issuing-map identity. */
	cuckoo_map &operator=(const cuckoo_map &) = delete;
	/** @brief Keep this map's address stable for every prepared query. */
	cuckoo_map(cuckoo_map &&) = delete;
	/** @brief Keep this map's address stable for every prepared query. */
	cuckoo_map &operator=(cuckoo_map &&) = delete;

	/**
	 * @brief Compute and prefetch both candidate buckets without reading entries.
	 * @param key Semantic key copied into the returned query.
	 * @return Map-bound query valid until this map is destroyed.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE prepared_query prepare(const Key &key) const noexcept
	{
		const auto [h1, h2] = hash_pair(key);
		const size_type first = h1 & mask_;
		const size_type second = h2 & mask_;
		prefetch_buckets_(first, second);
		return prepared_query(this, key, first, second);
	}

	/**
	 * @brief Search current contents using a query issued by this map.
	 * @param query Copied lookup facts; intervening mutations do not invalidate them.
	 * @return Current value or null. A foreign issuing-map identity terminates.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE Value *find(const prepared_query &query) noexcept
	{
		if (KINETUM_UNLIKELY(query.owner_ != this)) {
			std::terminate();
		}
		return find_buckets_(query.key_, query.first_, query.second_);
	}

	/**
	 * @brief Search current contents without granting mutable value access.
	 * @param query Facts issued by this map; a foreign identity terminates.
	 * @return Immutable current value, or null when absent.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE const Value *find(const prepared_query &query) const noexcept
	{
		return const_cast<cuckoo_map *>(this)->find(query);
	}

	/**
	 * @brief Find value by key.
	 *
	 * O(1) worst-case: checks at most two candidate buckets.
	 *
	 * @param key Key to find
	 * @return Pointer to value if found, nullptr otherwise
	 */
	[[nodiscard]] KINETUM_HOT KINETUM_ALWAYS_INLINE Value *find(const Key &key) noexcept
	{
		const auto [h1, h2] = hash_pair(key);

		const size_type first = h1 & mask_;
		const size_type second = h2 & mask_;
		prefetch_buckets_(first, second);
		return find_buckets_(key, first, second);
	}

	/**
	 * @brief Find an immutable value by key.
	 * @param key Key to find.
	 * @return Immutable value pointer, or nullptr when absent.
	 */
	[[nodiscard]] KINETUM_HOT KINETUM_ALWAYS_INLINE const Value *find(const Key &key) const noexcept
	{
		return const_cast<cuckoo_map *>(this)->find(key);
	}

	/**
	 * @brief Check if key exists.
	 *
	 * O(1) worst-case.
	 *
	 * @param key Key to find.
	 * @return True only when the exact key is present.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE bool contains(const Key &key) const noexcept
	{
		return find(key) != nullptr;
	}

	/**
	 * @brief Insert or update key-value pair.
	 *
	 * O(1) expected, may trigger displacement chain.
	 *
	 * @param key Key to insert
	 * @param value Value to insert
	 * @return true if inserted/updated, false if table is full
	 */
	KINETUM_HOT
	bool insert(const Key &key, const Value &value) noexcept
	{
		// Check if key already exists (update case)
		if (Value *existing = find(key)) {
			*existing = value;
			return true;
		}

		// Try to insert into first table
		const auto [h1, h2] = hash_pair(key);
		if (table1_[h1 & mask_].try_insert(key, value)) {
			++size_;
			return true;
		}

		// Try to insert into second table
		if (table2_[h2 & mask_].try_insert(key, value)) {
			++size_;
			return true;
		}

		// Both buckets full - start cuckoo displacement
		return cuckoo_insert(key, value, h1);
	}

	/**
	 * @brief Remove key from table.
	 *
	 * O(1) worst-case.
	 *
	 * @param key Key to remove
	 * @return true if removed, false if not found
	 */
	KINETUM_ALWAYS_INLINE
	bool erase(const Key &key) noexcept
	{
		const auto [h1, h2] = hash_pair(key);

		if (table1_[h1 & mask_].remove(key)) {
			--size_;
			return true;
		}

		if (table2_[h2 & mask_].remove(key)) {
			--size_;
			return true;
		}

		return false;
	}

	/**
	 * @brief Get number of elements.
	 * @return Exact occupied entry count.
	 */
	[[nodiscard]] size_type size() const noexcept
	{
		return size_;
	}

    private:
	/**
	 * @brief Prefetch stable bucket storage without inspecting mutable entries.
	 * @param first First-table bucket ordinal.
	 * @param second Second-table bucket ordinal.
	 */
	KINETUM_ALWAYS_INLINE void prefetch_buckets_(size_type first, size_type second) const noexcept
	{
		KINETUM_PREFETCH_L1(&table1_[first]);
		KINETUM_PREFETCH_L1(&table2_[second]);
	}

	/**
	 * @brief Search the two current candidate buckets in canonical order.
	 * @param key Semantic key to compare.
	 * @param first First-table bucket ordinal.
	 * @param second Second-table bucket ordinal.
	 * @return Current value, or null when absent from both candidates.
	 */
	[[nodiscard]] KINETUM_ALWAYS_INLINE Value *find_buckets_(const Key &key, size_type first,
								 size_type second) noexcept
	{
		if (Value *value = table1_[first].find(key)) {
			return value;
		}
		return table2_[second].find(key);
	}

	/** Cache-aligned bucket representation for this key/value pair. */
	using bucket_type = cuckoo_bucket<Key, Value>;

	/**
	 * @brief Snapshot of one bucket entry before cuckoo displacement.
	 *
	 * `cuckoo_insert` records displaced entries in this form so a max-kicks
	 * failure can restore the table to its pre-insert state. This is the
	 * failure-atomic insertion contract.
	 */
	struct undo_record {
		bool use_table1{true};	  ///< Select the first or second table.
		size_type bucket_idx{0};  ///< Exact bucket ordinal.
		size_type entry_idx{0};	  ///< Exact entry ordinal within the bucket.
		Key key{};		  ///< Prior semantic key.
		Value value{};		  ///< Prior value.
		bool occupied{false};	  ///< Prior entry-ownership state.
	};

	/**
	 * @brief Compute hash pair for cuckoo tables.
	 *
	 * Derive both candidates from the same semantic hash with distinct mixes.
	 *
	 * @param key Semantic key consumed by the explicit caller hasher.
	 * @return First- and second-table candidate hashes.
	 */
	KINETUM_ALWAYS_INLINE
	std::pair<uint64_t, uint64_t> hash_pair(const Key &key) const noexcept
	{
		const uint64_t h = hasher_(key);
		const uint64_t h1 = splitmix64(h);
		const uint64_t h2 = splitmix64(h ^ 0xc4ceb9fe1a85ec53ULL);

		return {h1, h2};
	}

	/**
	 * @brief Cuckoo displacement insertion.
	 *
	 * Displaces existing elements to make room for new insertion.
	 * Gives up after CUCKOO_MAX_KICKS to prevent infinite loops.
	 * Failure is atomic: existing entries are restored before returning false.
	 *
	 * @param key New semantic key after both direct candidates were full.
	 * @param value New value paired with @p key.
	 * @param h1 First-table candidate hash for @p key.
	 * @return true after exact insertion; false after restoring every displacement.
	 */
	bool cuckoo_insert(Key key, Value value, uint64_t h1) noexcept
	{
		std::size_t undo_count = 0;

		auto restore = [&]() noexcept {
			while (undo_count > 0) {
				const auto &rec = undo_log_[--undo_count];
				auto &bucket = rec.use_table1 ? table1_[rec.bucket_idx] : table2_[rec.bucket_idx];
				auto &entry = bucket.entries[rec.entry_idx];
				entry.key = rec.key;
				entry.value = rec.value;
				entry.occupied = rec.occupied;
			}
		};

		// Alternate between tables during displacement
		bool use_table1 = true;
		uint64_t h = h1;

		for (std::size_t kick = 0; kick < CUCKOO_MAX_KICKS; ++kick) {
			auto &table = use_table1 ? table1_ : table2_;
			const size_type bucket_idx = h & mask_;
			auto &bucket = table[bucket_idx];

			// Try to find empty slot
			if (bucket.try_insert(key, value)) {
				++size_;
				return true;
			}

			// Rotate victims deterministically instead of always evicting entry zero.
			const std::size_t victim_idx = kick % CUCKOO_BUCKET_SIZE;
			auto &victim = bucket.entries[victim_idx];
			undo_log_[undo_count++] = undo_record{use_table1, bucket_idx,	victim_idx,
							      victim.key, victim.value, victim.occupied};
			Key displaced_key = victim.key;
			Value displaced_value = victim.value;
			victim.key = key;
			victim.value = value;
			key = displaced_key;
			value = displaced_value;

			// Compute new hash for displaced element
			auto [new_h1, new_h2] = hash_pair(key);

			// Move to other table
			use_table1 = !use_table1;
			h = use_table1 ? new_h1 : new_h2;
		}

		// Failed to insert after max kicks. Leave the table unchanged so callers
		// can fail closed, resize, or shed load without losing existing entries.
		restore();
		return false;
	}

	/**
	 * @brief Round up to next power of 2.
	 * @param n Positive requested bucket count.
	 * @return Rounded count, or zero when not representable.
	 */
	// Use canonical implementation from bits.hpp (has overflow protection + early exit)
	static constexpr size_type next_power_of_2(size_type n) noexcept
	{
		return static_cast<size_type>(next_power_of_2_64(static_cast<uint64_t>(n)));
	}

	/**
	 * @brief Validate and normalize one requested bucket count.
	 * @param requested Positive requested bucket count.
	 * @return Representable power-of-two bucket count.
	 * @throws std::invalid_argument when @p requested is zero or cannot be rounded.
	 */
	static size_type normalize_bucket_count_(size_type requested)
	{
		if (requested == 0u) {
			throw std::invalid_argument("cuckoo_map: bucket count must be positive");
		}
		const size_type rounded = next_power_of_2(requested);
		if (rounded == 0) {
			throw std::invalid_argument("cuckoo_map: bucket count is too large");
		}
		return rounded;
	}

	/**
	 * @brief Require explicit table-storage ownership.
	 * @param memory_resource Candidate resource that must outlive the map.
	 * @return The same non-null resource.
	 * @throws std::invalid_argument when @p memory_resource is null.
	 */
	[[nodiscard]] static std::pmr::memory_resource *
	require_memory_resource_(std::pmr::memory_resource *memory_resource)
	{
		if (memory_resource == nullptr) {
			throw std::invalid_argument("cuckoo_map: memory resource is null");
		}
		return memory_resource;
	}

	size_type num_buckets_;			  ///< Power-of-two buckets per table.
	size_type mask_;			  ///< Bucket-index mask.
	std::pmr::vector<bucket_type> table1_;	  ///< First candidate table.
	std::pmr::vector<bucket_type> table2_;	  ///< Second candidate table.
	std::pmr::vector<undo_record> undo_log_;  ///< Preallocated failure-atomic displacement log.
	size_type size_{0};			  ///< Exact occupied entry count.
	Hash hasher_{};				  ///< Explicit nonthrowing semantic hasher.
};

}  // namespace kinetum::algo
