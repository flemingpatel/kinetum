// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file cache.hpp
 * @brief Cache data structures and eviction policies.
 * @author Fleming Patel
 *
 * Contains:
 * - LRU Cache: Least Recently Used eviction policy
 * - Cache-aligned allocations
 * - Intrusive list utilities
 *
 * These are reusable C++ SDK mechanisms with no current platform-runtime
 * dependency. `lru_cache` uses std::unordered_map and heap allocation on
 * insert/evict.
 *
 * `lru_cache` is not suitable for per-packet hot-path flow/session state.
 * For hot-path state, use cuckoo_map plus preallocated slab/pool storage.
 */

#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <new>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

// =============================================================================
// Intrusive LRU Node (zero-allocation linked list)
// =============================================================================

/**
 * @brief Base class for intrusive LRU list nodes.
 *
 * Inherit from this to make any structure LRU-evictable without
 * additional heap allocations for list nodes.
 */
class lru_list;

/**
 * @brief Intrusive node with one exact list owner while linked.
 *
 * Destroying a linked node terminates because the list would otherwise retain
 * a dangling authority. A list clear, pop, or unlink detaches the node first.
 */
class lru_node {
    public:
	/** @brief Construct one detached node. */
	lru_node() noexcept = default;
	/** @brief A linked identity cannot be copied. */
	lru_node(const lru_node &) = delete;
	/** @brief A linked identity cannot be copy-assigned. */
	lru_node &operator=(const lru_node &) = delete;
	/** @brief Stable intrusive node addresses cannot move. */
	lru_node(lru_node &&) = delete;
	/** @brief Stable intrusive node addresses cannot be move-assigned. */
	lru_node &operator=(lru_node &&) = delete;
	/** @brief Destruction requires the node to be detached from every list. */
	~lru_node()
	{
		if (owner_ != nullptr) {
			std::terminate();
		}
	}

    private:
	friend class lru_list;
	lru_node *prev_{nullptr};   ///< Previous node while linked.
	lru_node *next_{nullptr};   ///< Next node while linked.
	lru_list *owner_{nullptr};  ///< Exact list owner while linked.
};

/**
 * @brief Intrusive doubly-linked list for LRU tracking.
 *
 * Zero-allocation LRU list. Nodes must inherit from lru_node.
 * Head is MRU (most recently used), tail is LRU (least recently used).
 *
 * @par Thread Safety
 * One caller owns all list and node operations. No method synchronizes.
 */
class lru_list {
    public:
	/** @brief Construct one empty intrusive list. */
	constexpr lru_list() noexcept = default;
	/** @brief Detach every remaining node before releasing list identity. */
	~lru_list()
	{
		clear();
	}
	/** @brief One intrusive node set cannot be copied. */
	lru_list(const lru_list &) = delete;
	/** @brief One intrusive node set cannot be copy-assigned. */
	lru_list &operator=(const lru_list &) = delete;
	/** @brief Linked node owner pointers prevent list movement. */
	lru_list(lru_list &&) = delete;
	/** @brief Linked node owner pointers prevent list move assignment. */
	lru_list &operator=(lru_list &&) = delete;

	/**
	 * @brief Move one exactly linked node to the head.
	 * @param node Candidate node already owned by this list.
	 * @return True on exact ownership; false without mutation otherwise.
	 */
	[[nodiscard]]
	KINETUM_ALWAYS_INLINE bool touch(lru_node *node) noexcept
	{
		if (node == nullptr || node->owner_ != this) {
			return false;
		}
		if (node != head_) {
			detach_(node);
			link_front_(node);
		}
		return true;
	}

	/**
	 * @brief Add one detached node at the head.
	 * @param node Candidate detached node.
	 * @return True when this list acquired the node; false without mutation otherwise.
	 */
	[[nodiscard]]
	KINETUM_ALWAYS_INLINE bool push_front(lru_node *node) noexcept
	{
		if (node == nullptr || node->owner_ != nullptr || node->prev_ != nullptr || node->next_ != nullptr) {
			return false;
		}
		link_front_(node);
		return true;
	}

	/** @return Detached least-recently-used node, or null when empty. */
	[[nodiscard]]
	KINETUM_ALWAYS_INLINE lru_node *pop_back() noexcept
	{
		if (!tail_)
			return nullptr;

		lru_node *node = tail_;
		detach_(node);
		return node;
	}

	/**
	 * @brief Remove one exact member from this list.
	 * @param node Candidate exact member.
	 * @return True when detached; false without mutation for null or foreign nodes.
	 */
	[[nodiscard]]
	KINETUM_ALWAYS_INLINE bool unlink(lru_node *node) noexcept
	{
		if (node == nullptr || node->owner_ != this) {
			return false;
		}
		detach_(node);
		return true;
	}

	/** @return Borrowed least-recently-used node, or null when empty. */
	[[nodiscard]] constexpr lru_node *tail() const noexcept
	{
		return tail_;
	}

	/** @return Borrowed most-recently-used node, or null when empty. */
	[[nodiscard]] constexpr lru_node *head() const noexcept
	{
		return head_;
	}

	/** @return Exact linked-node count. */
	[[nodiscard]] constexpr std::size_t size() const noexcept
	{
		return size_;
	}

	/** @return True exactly when no node is linked. */
	[[nodiscard]] constexpr bool empty() const noexcept
	{
		return size_ == 0;
	}

	/** @brief Detach every node without reclaiming caller-owned storage. */
	void clear() noexcept
	{
		lru_node *node = head_;
		std::size_t detached = 0u;
		while (node != nullptr && detached < size_) {
			if (node->owner_ != this) {
				std::terminate();
			}
			lru_node *next = node->next_;
			node->prev_ = nullptr;
			node->next_ = nullptr;
			node->owner_ = nullptr;
			node = next;
			++detached;
		}
		if (node != nullptr || detached != size_) {
			std::terminate();
		}
		head_ = nullptr;
		tail_ = nullptr;
		size_ = 0;
	}

    private:
	/** @brief Link one proven-detached node at the head. @param node Exact detached node. */
	void link_front_(lru_node *node) noexcept
	{
		node->prev_ = nullptr;
		node->next_ = head_;
		node->owner_ = this;
		if (head_ != nullptr) {
			head_->prev_ = node;
		} else {
			tail_ = node;
		}
		head_ = node;
		++size_;
	}

	/** @brief Detach one proven member and clear its owner identity. @param node Exact member. */
	void detach_(lru_node *node) noexcept
	{
		if (node->prev_ != nullptr) {
			node->prev_->next_ = node->next_;
		} else {
			head_ = node->next_;
		}
		if (node->next_ != nullptr) {
			node->next_->prev_ = node->prev_;
		} else {
			tail_ = node->prev_;
		}
		node->prev_ = nullptr;
		node->next_ = nullptr;
		node->owner_ = nullptr;
		if (size_ == 0u) {
			std::terminate();
		}
		--size_;
	}

	lru_node *head_{nullptr};  ///< Most-recently-used member, or null when empty.
	lru_node *tail_{nullptr};  ///< Least-recently-used member, or null when empty.
	std::size_t size_{0};	   ///< Exact linked-node population.
};

// =============================================================================
// LRU Cache (Hash Map + LRU List)
// =============================================================================

/**
 * @brief LRU cache with average O(1) hash lookup, insertion, and eviction.
 *
 * Uses std::unordered_map for fast key lookup and intrusive LRU list
 * for eviction ordering. Cache entries are heap-allocated.
 *
 * @tparam K Key type (must be hashable)
 * @tparam V Value type
 * @tparam Hash Hash function for keys
 *
 * @par Thread Safety
 * One cold caller owns lookup-order mutation, insertion, removal, and
 * destruction. External synchronization is required for shared use.
 */
template <typename K, typename V, typename Hash = std::hash<K>>
class lru_cache {
    private:
	/** @brief Heap-owned cache entry with embedded exact list identity. */
	struct entry : lru_node {
		K key;	  ///< Immutable lookup identity while the entry is resident.
		V value;  ///< Caller-owned cached value.

		/**
		 * @brief Construct one detached cache entry.
		 * @param k Key forwarded into owned storage.
		 * @param v Value forwarded into owned storage.
		 */
		template <typename KK, typename VV>
		entry(KK &&k, VV &&v)
			: key(std::forward<KK>(k))
			, value(std::forward<VV>(v))
		{
		}
	};

    public:
	/** Callback invoked before eviction membership changes. */
	using eviction_callback = std::function<void(const K &, V &)>;

	/**
     * @brief Construct LRU cache.
     * @param capacity Maximum number of entries
     * @param on_evict Optional callback when entry is evicted
	 * @throws std::invalid_argument when @p capacity is zero, or any allocation
	 *         exception from complete map reservation.
     */
	explicit lru_cache(std::size_t capacity, eviction_callback on_evict = nullptr)
		: capacity_(capacity)
		, on_evict_(std::move(on_evict))
	{
		if (capacity_ == 0) {
			throw std::invalid_argument("lru_cache: capacity must be greater than 0");
		}
		map_.reserve(capacity);
	}

	/** @brief Detach and reclaim every entry. */
	~lru_cache()
	{
		clear();
	}

	// Non-copyable, non-movable
	// Move operations deleted because lru_list contains raw pointers (head_/tail_)
	// that would become stale in the moved-from object. The source lru_list's
	// head_/tail_ pointers would still reference entries owned by the destination,
	// leaving the moved-from object in an inconsistent state (size_ > 0 but
	// map_ empty, lru_ pointers dangling). No implicit move operation can
	// preserve both containers' invariants, so movement is prohibited.
	lru_cache(const lru_cache &) = delete;
	lru_cache &operator=(const lru_cache &) = delete;
	lru_cache(lru_cache &&) = delete;
	lru_cache &operator=(lru_cache &&) = delete;

	/**
     * @brief Get value by key, updating LRU order.
	 * @param key Key to look up
	 * @return Pointer to value, or nullptr if not found
	 * @throws Any exception emitted by the caller's hash or equality operation.
     */
	KINETUM_ALWAYS_INLINE
	V *get(const K &key)
	{
		auto it = map_.find(key);
		if (it == map_.end()) {
			return nullptr;
		}

		// Touch to mark as recently used
		if (!lru_.touch(it->second.get())) {
			std::terminate();
		}
		return &it->second->value;
	}

	/**
     * @brief Get value without updating LRU order (peek).
	 * @param key Key to look up
	 * @return Pointer to value, or nullptr if not found
	 * @throws Any exception emitted by the caller's hash or equality operation.
     */
	[[nodiscard]] const V *peek(const K &key) const
	{
		auto it = map_.find(key);
		return (it != map_.end()) ? &it->second->value : nullptr;
	}

	/**
     * @brief Insert or update entry.
     * @param key Key
	 * @param value Value
	 * @return true if inserted, false if updated existing
	 * @throws Any exception from allocation, key/value construction or
	 *         assignment, hashing, equality, or the pre-eviction callback.
     */
	template <typename KK, typename VV>
	bool put(KK &&key, VV &&value)
	{
		auto it = map_.find(key);

		if (it != map_.end()) {
			// Update existing
			it->second->value = std::forward<VV>(value);
			if (!lru_.touch(it->second.get())) {
				std::terminate();
			}
			return false;
		}

		// Evict if at capacity
		while (lru_.size() >= capacity_) {
			evict_one();
		}

		// Insert new entry
		auto entry_ptr = std::make_unique<entry>(std::forward<KK>(key), std::forward<VV>(value));
		const K map_key = entry_ptr->key;
		auto [it_inserted, inserted] = map_.emplace(map_key, std::move(entry_ptr));
		if (!inserted) {
			std::terminate();
		}
		if (!lru_.push_front(it_inserted->second.get())) {
			std::terminate();
		}
		return true;
	}

	/**
     * @brief Remove entry by key.
	 * @param key Key to remove
	 * @return true if removed, false if not found
	 * @throws Any exception emitted by the caller's hash or equality operation.
     */
	bool erase(const K &key)
	{
		auto it = map_.find(key);
		if (it == map_.end()) {
			return false;
		}

		if (!lru_.unlink(it->second.get())) {
			std::terminate();
		}
		map_.erase(it);
		return true;
	}

	/** @brief Detach and reclaim every cache entry. */
	void clear()
	{
		lru_.clear();
		map_.clear();
	}

	/** @return Exact current entry count. */
	[[nodiscard]] std::size_t size() const noexcept
	{
		return map_.size();
	}

	/** @return Construction-time maximum entry count. */
	[[nodiscard]] std::size_t capacity() const noexcept
	{
		return capacity_;
	}

	/** @return True exactly when the cache has no entry. */
	[[nodiscard]] bool empty() const noexcept
	{
		return map_.empty();
	}

	/** @return True when another distinct key requires one eviction. */
	[[nodiscard]] bool full() const noexcept
	{
		return map_.size() >= capacity_;
	}

	/**
	 * @param key Key to inspect.
	 * @return True when the key is present.
	 * @throws Any exception emitted by the caller's hash or equality operation.
	 */
	[[nodiscard]] bool contains(const K &key) const
	{
		return map_.find(key) != map_.end();
	}

    private:
	/**
	 * @brief Evict the exact least-recently-used entry.
	 * @throws Any exception from hash/equality lookup or the callback. A callback
	 *         exception precedes structural membership mutation.
	 */
	void evict_one()
	{
		auto *node = lru_.tail();
		if (!node)
			return;

		auto *e = static_cast<entry *>(node);
		auto it = map_.find(e->key);
		if (it == map_.end() || it->second.get() != e) {
			std::terminate();
		}
		if (on_evict_) {
			on_evict_(e->key, e->value);
		}
		if (!lru_.unlink(node)) {
			std::terminate();
		}
		map_.erase(it);
	}

	std::size_t capacity_;	      ///< Maximum resident key population.
	eviction_callback on_evict_;  ///< Optional callback completed before eviction mutation.
	lru_list lru_;		      ///< Exact recency ordering over every map entry.
	std::unordered_map<K, std::unique_ptr<entry>, Hash> map_;  ///< Sole key-to-entry ownership map.
};

// =============================================================================
// Cache-Aligned Allocation Helpers
// =============================================================================

/**
 * @brief Allocate cache-line aligned memory (POSIX).
 *
 * @param size Size in bytes
 * @return Aligned pointer that must be passed to aligned_free_cacheline(), or
 *         null for zero, overflow, or allocation failure.
 */
inline void *aligned_alloc_cacheline(std::size_t size)
{
	if (size == 0u) {
		return nullptr;
	}
	const std::size_t aligned_size = align_to_cache_line(size);
	return aligned_size != 0u ? std::aligned_alloc(CACHE_LINE_SIZE, aligned_size) : nullptr;
}

/**
 * @brief Free cache-line-aligned memory.
 * @param ptr Pointer returned by aligned_alloc_cacheline(), including null.
 */
inline void aligned_free_cacheline(void *ptr)
{
	std::free(ptr);
}

/**
 * @brief Deleter for one cache-line-aligned object or raw allocation.
 */
struct aligned_deleter {
	template <typename T>
	/** @brief Destroy and release one typed object. @param ptr Owned object or null. */
	void operator()(T *ptr) const noexcept
	{
		if (ptr) {
			ptr->~T();
			aligned_free_cacheline(ptr);
		}
	}

	/** @brief Release one untyped allocation. @param ptr Owned allocation or null. */
	void operator()(void *ptr) const noexcept
	{
		if (ptr) {
			aligned_free_cacheline(ptr);
		}
	}
};

/**
 * @brief Create one cache-line-aligned object.
 * @tparam T Object type.
 * @tparam Args Constructor argument types.
 * @param args Arguments forwarded to the object constructor.
 * @return Owning pointer, or null when aligned allocation fails.
 * @throws Any exception emitted by the object constructor.
 */
template <typename T, typename... Args>
std::unique_ptr<T, aligned_deleter> make_aligned(Args &&...args)
{
	void *mem = aligned_alloc_cacheline(sizeof(T));
	if (!mem)
		return nullptr;
	try {
		return std::unique_ptr<T, aligned_deleter>(new (mem) T(std::forward<Args>(args)...));
	} catch (...) {
		aligned_free_cacheline(mem);
		throw;
	}
}

}  // namespace kinetum::algo
