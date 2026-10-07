// Copyright (c) 2026 Fleming Patel. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

/**
 * @file graph.hpp
 * @brief Graph algorithms for pipeline DAG processing.
 * @author Fleming Patel
 *
 * This is the canonical generic graph implementation. Axiom uses it to
 * produce the deterministic order consumed by Gluon planning.
 *
 * Contains:
 * - Topological sort (Kahn's algorithm)
 * - DAG representation
 * - Successor and indegree queries required by that ordering
 *
 * Design:
 * - Template-based for any node ID type (string, int, etc.)
 * - Header-only for direct inlining and no runtime-library dependency
 * - Deterministic ordering (smallest ID first for reproducibility)
 *
 * Used by:
 * - Axiom validation and canonical ordering
 * - Gluon planning through Axiom's canonical result
 *
 * The same definitions serve both supported little-endian target tuples.
 */

#include <algorithm>
#include <cstddef>
#include <functional>
#include <queue>
#include <unordered_map>
#include <vector>

#include <kinetum/algo/platform.hpp>

namespace kinetum::algo
{

// =============================================================================
// DAG Graph Structure
// =============================================================================

/**
 * @brief Directed Acyclic Graph representation.
 *
 * Generic DAG structure with one record per node and average O(1) identity
 * lookup. Suitable for pipeline stage and dependency graphs.
 *
 * @tparam NodeId Node identifier type (e.g., std::string, int)
 */
template <typename NodeId>
class dag {
    public:
	using node_id_type = NodeId;  ///< Caller-owned node identity type.

	/**
	 * @brief Add a node to the graph.
	 * @param id Node identifier
	 * @return true if added, false if already exists
	 */
	bool add_node(const NodeId &id)
	{
		return nodes_.try_emplace(id).second;
	}

	/**
	 * @brief Add a directed edge from -> to.
	 * @param from Source node ID
	 * @param to Destination node ID
	 * @return true if added, false if edge already exists or nodes missing
	 */
	bool add_edge(const NodeId &from, const NodeId &to)
	{
		auto from_node = nodes_.find(from);
		auto to_node = nodes_.find(to);
		if (from_node == nodes_.end() || to_node == nodes_.end()) {
			return false;
		}

		auto &succs = from_node->second.successors;
		if (std::find(succs.begin(), succs.end(), to) != succs.end()) {
			return false;  // Edge already exists
		}

		succs.push_back(to);
		++to_node->second.indegree;
		return true;
	}

	/**
	 * @brief Get successors of a node.
	 * @param id Node identity to find.
	 * @return Pointer to successor list, or nullptr if node doesn't exist
	 */
	[[nodiscard]] const std::vector<NodeId> *successors(const NodeId &id) const
	{
		auto it = nodes_.find(id);
		return (it != nodes_.end()) ? &it->second.successors : nullptr;
	}

	/**
	 * @brief Get indegree of a node.
	 * @param id Node identity to inspect.
	 * @return Number of incoming edges, or -1 when the node is absent.
	 */
	[[nodiscard]] int indegree(const NodeId &id) const
	{
		auto it = nodes_.find(id);
		return (it != nodes_.end()) ? it->second.indegree : -1;
	}

	/**
	 * @brief Get number of nodes.
	 * @return Current node population.
	 */
	[[nodiscard]] std::size_t node_count() const
	{
		return nodes_.size();
	}

	/**
	 * @brief Get all node IDs in deterministic (sorted) order.
	 *
	 * DETERMINISM: Returns node IDs sorted by natural ordering to ensure
	 * reproducible iteration across runs/platforms. Hash-map iteration
	 * order depends on hash bucket layout which varies.
	 * (same inputs -> identical outputs)
	 *
	 * @return Sorted copy of every node identity.
	 */
	[[nodiscard]] std::vector<NodeId> node_ids() const
	{
		std::vector<NodeId> ids;
		ids.reserve(nodes_.size());
		for (const auto &entry : nodes_) {
			ids.push_back(entry.first);
		}
		std::sort(ids.begin(), ids.end());
		return ids;
	}

    private:
	/** Complete topology facts owned by one node identity. */
	struct node_record {
		std::vector<NodeId> successors;	 ///< Directed successor identities.
		int indegree{0};		 ///< Number of incoming edges.
	};
	std::unordered_map<NodeId, node_record> nodes_;	 ///< Sole node/topology authority.
};

// =============================================================================
// Topological Sort (Kahn's Algorithm)
// =============================================================================

/**
 * @brief Result of topological sort.
 */
template <typename NodeId>
struct topo_sort_result {
	bool success{false};		    ///< true if DAG is valid (no cycles)
	std::vector<NodeId> order;	    ///< Topological order (empty if cycle detected)
	std::vector<NodeId> blocked_nodes;  ///< Kahn-blocked cycle and downstream nodes on failure.
};

/**
 * @brief Perform stable topological sort using Kahn's algorithm.
 *
 * Returns nodes in topological order (all predecessors before successors).
 * Uses a priority queue for deterministic ordering (smallest ID first).
 *
 * DETERMINISM: This implementation ensures identical output across runs/platforms
 * by sorting zero-indegree nodes before seeding the priority queue:
 * same inputs -> identical outputs.
 *
 * @tparam NodeId Node identifier type
 * @param g The DAG to sort
 * @return Result containing order or cycle information
 *
 * Complexity: O(E + V log V) where V = nodes and E = edges. Each node enters
 *             the priority queue once; deterministic seed sorting is bounded
 *             by the same term.
 */
template <typename NodeId>
[[nodiscard]] topo_sort_result<NodeId> topological_sort(const dag<NodeId> &g)
{
	topo_sort_result<NodeId> result;

	// Copy indegree map (we'll modify it)
	std::unordered_map<NodeId, int> indegree;
	for (const auto &id : g.node_ids()) {
		indegree[id] = g.indegree(id);
	}

	// Priority queue for deterministic ordering (smallest first with std::greater)
	std::priority_queue<NodeId, std::vector<NodeId>, std::greater<NodeId>> ready;

	// Collect zero-indegree nodes into a sorted vector first.
	// Iteration over unordered_map is non-deterministic (order depends on hash
	// bucket layout, which varies across runs/platforms). Even though we use a
	// priority queue, we must ensure deterministic seeding for reproducibility.
	// Cost: O(k log k) where k = zero-indegree count (typically k=1 for single RX)
	std::vector<NodeId> zero_indegree_nodes;
	zero_indegree_nodes.reserve(indegree.size());
	for (const auto &[id, deg] : indegree) {
		if (deg == 0) {
			zero_indegree_nodes.push_back(id);
		}
	}
	std::sort(zero_indegree_nodes.begin(), zero_indegree_nodes.end());
	for (const auto &id : zero_indegree_nodes) {
		ready.push(id);
	}

	// Kahn's algorithm
	while (!ready.empty()) {
		NodeId current = ready.top();
		ready.pop();
		result.order.push_back(current);

		// Reduce indegree of successors
		if (auto *succs = g.successors(current)) {
			for (const auto &succ : *succs) {
				indegree[succ]--;
				if (indegree[succ] == 0) {
					ready.push(succ);
				}
			}
		}
	}

	// Check for cycles
	if (result.order.size() == g.node_count()) {
		result.success = true;
	} else {
		// Kahn's algorithm leaves both cycle members and nodes downstream of a
		// cycle blocked with positive residual indegree.
		for (const auto &[id, deg] : indegree) {
			if (deg > 0) {
				result.blocked_nodes.push_back(id);
			}
		}
		std::sort(result.blocked_nodes.begin(), result.blocked_nodes.end());
		result.order.clear();  // Invalid order
	}

	return result;
}

}  // namespace kinetum::algo
