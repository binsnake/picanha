#include "picanha/analysis/cfg.hpp"
#include <spdlog/spdlog.h>
#include <queue>
#include <stack>
#include <algorithm>

namespace picanha::analysis {

BasicBlock& CFG::create_block(Address start_address) {
    BlockId id = next_block_id_++;
    auto [it, inserted] = blocks_.emplace(id, BasicBlock(id, start_address));
    address_to_block_[start_address] = id;
    return it->second;
}

BasicBlock& CFG::get_block(BlockId id) {
    return blocks_.at(id);
}

const BasicBlock& CFG::get_block(BlockId id) const {
    return blocks_.at(id);
}

BasicBlock* CFG::find_block(BlockId id) {
    auto it = blocks_.find(id);
    return it != blocks_.end() ? &it->second : nullptr;
}

const BasicBlock* CFG::find_block(BlockId id) const {
    auto it = blocks_.find(id);
    return it != blocks_.end() ? &it->second : nullptr;
}

BasicBlock* CFG::find_block_at(Address addr) {
    for (auto& [id, block] : blocks_) {
        if (block.contains(addr)) {
            return &block;
        }
    }
    return nullptr;
}

const BasicBlock* CFG::find_block_at(Address addr) const {
    for (const auto& [id, block] : blocks_) {
        if (block.contains(addr)) {
            return &block;
        }
    }
    return nullptr;
}

BasicBlock* CFG::find_block_starting_at(Address addr) {
    auto it = address_to_block_.find(addr);
    if (it != address_to_block_.end()) {
        return find_block(it->second);
    }
    return nullptr;
}

const BasicBlock* CFG::find_block_starting_at(Address addr) const {
    auto it = address_to_block_.find(addr);
    if (it != address_to_block_.end()) {
        return find_block(it->second);
    }
    return nullptr;
}

std::vector<BasicBlock*> CFG::get_all_blocks() {
    std::vector<BasicBlock*> result;
    result.reserve(blocks_.size());
    for (auto& [id, block] : blocks_) {
        result.push_back(&block);
    }
    return result;
}

std::vector<const BasicBlock*> CFG::get_all_blocks() const {
    std::vector<const BasicBlock*> result;
    result.reserve(blocks_.size());
    for (const auto& [id, block] : blocks_) {
        result.push_back(&block);
    }
    return result;
}

void CFG::add_edge(BlockId from, BlockId to, EdgeType type) {
    auto* from_block = find_block(from);
    auto* to_block = find_block(to);

    if (from_block && to_block) {
        BlockEdge edge;
        edge.target = to;
        edge.type = type;
        from_block->add_successor(edge);
        to_block->add_predecessor(from);
    }
}

void CFG::add_edge(BasicBlock& from, BasicBlock& to, EdgeType type) {
    add_edge(from.id(), to.id(), type);
}

void CFG::set_entry_block(BlockId id) {
    entry_block_ = id;
    if (auto* block = find_block(id)) {
        block->set_entry_block(true);
    }
}

BasicBlock* CFG::entry_block() {
    return find_block(entry_block_);
}

const BasicBlock* CFG::entry_block() const {
    return find_block(entry_block_);
}

void CFG::add_exit_block(BlockId id) {
    exit_blocks_.push_back(id);
    if (auto* block = find_block(id)) {
        block->set_exit_block(true);
    }
}

void CFG::dfs_preorder(BlockVisitor visitor) {
    if (entry_block_ == INVALID_BLOCK_ID) return;

    std::unordered_set<BlockId> visited;
    dfs_preorder_impl(entry_block_, visitor, visited);
}

void CFG::dfs_postorder(BlockVisitor visitor) {
    if (entry_block_ == INVALID_BLOCK_ID) return;

    std::unordered_set<BlockId> visited;
    dfs_postorder_impl(entry_block_, visitor, visited);
}

void CFG::dfs_preorder_impl(BlockId id, BlockVisitor& visitor,
                            std::unordered_set<BlockId>& visited) {
    if (visited.count(id)) return;
    visited.insert(id);

    auto* block = find_block(id);
    if (!block) return;

    visitor(*block);

    for (const auto& edge : block->successors()) {
        dfs_preorder_impl(edge.target, visitor, visited);
    }
}

void CFG::dfs_postorder_impl(BlockId id, BlockVisitor& visitor,
                             std::unordered_set<BlockId>& visited) {
    if (visited.count(id)) return;
    visited.insert(id);

    auto* block = find_block(id);
    if (!block) return;

    for (const auto& edge : block->successors()) {
        dfs_postorder_impl(edge.target, visitor, visited);
    }

    visitor(*block);
}

void CFG::dfs_preorder(ConstBlockVisitor visitor) const {
    if (entry_block_ == INVALID_BLOCK_ID) return;

    std::unordered_set<BlockId> visited;
    std::stack<BlockId> stack;
    stack.push(entry_block_);

    while (!stack.empty()) {
        BlockId id = stack.top();
        stack.pop();

        if (visited.count(id)) continue;
        visited.insert(id);

        const auto* block = find_block(id);
        if (!block) continue;

        visitor(*block);

        // Push successors in reverse order for correct traversal
        const auto& succs = block->successors();
        for (auto it = succs.rbegin(); it != succs.rend(); ++it) {
            stack.push(it->target);
        }
    }
}

void CFG::dfs_postorder(ConstBlockVisitor visitor) const {
    if (entry_block_ == INVALID_BLOCK_ID) return;

    std::unordered_set<BlockId> visited;
    std::unordered_set<BlockId> finished;
    std::stack<BlockId> stack;
    stack.push(entry_block_);

    while (!stack.empty()) {
        BlockId id = stack.top();

        if (finished.count(id)) {
            stack.pop();
            continue;
        }

        if (visited.count(id)) {
            // All successors processed
            stack.pop();
            finished.insert(id);
            if (const auto* block = find_block(id)) {
                visitor(*block);
            }
            continue;
        }

        visited.insert(id);

        const auto* block = find_block(id);
        if (!block) {
            stack.pop();
            continue;
        }

        for (const auto& edge : block->successors()) {
            if (!visited.count(edge.target)) {
                stack.push(edge.target);
            }
        }
    }
}

void CFG::bfs(BlockVisitor visitor) {
    if (entry_block_ == INVALID_BLOCK_ID) return;

    std::unordered_set<BlockId> visited;
    std::queue<BlockId> queue;
    queue.push(entry_block_);
    visited.insert(entry_block_);

    while (!queue.empty()) {
        BlockId id = queue.front();
        queue.pop();

        auto* block = find_block(id);
        if (!block) continue;

        visitor(*block);

        for (const auto& edge : block->successors()) {
            if (!visited.count(edge.target)) {
                visited.insert(edge.target);
                queue.push(edge.target);
            }
        }
    }
}

void CFG::bfs(ConstBlockVisitor visitor) const {
    if (entry_block_ == INVALID_BLOCK_ID) return;

    std::unordered_set<BlockId> visited;
    std::queue<BlockId> queue;
    queue.push(entry_block_);
    visited.insert(entry_block_);

    while (!queue.empty()) {
        BlockId id = queue.front();
        queue.pop();

        const auto* block = find_block(id);
        if (!block) continue;

        visitor(*block);

        for (const auto& edge : block->successors()) {
            if (!visited.count(edge.target)) {
                visited.insert(edge.target);
                queue.push(edge.target);
            }
        }
    }
}

std::vector<BlockId> CFG::reverse_postorder() const {
    std::vector<BlockId> result;
    result.reserve(blocks_.size());

    dfs_postorder([&result](const BasicBlock& block) {
        result.push_back(block.id());
    });

    std::reverse(result.begin(), result.end());
    return result;
}

void CFG::compute_dominators() {
    if (entry_block_ == INVALID_BLOCK_ID || blocks_.empty()) return;

    // Clear all dominators first
    for (auto& [id, block] : blocks_) {
        block.set_immediate_dominator(INVALID_BLOCK_ID);
    }

    // Entry block dominates itself
    auto* entry = find_block(entry_block_);
    if (entry) {
        entry->set_immediate_dominator(entry_block_);
    }

    // Get blocks in reverse postorder (excluding entry)
    auto rpo = reverse_postorder();
    
    // Iterative dataflow algorithm for dominators
    // Based on Cooper, Harvey, and Kennedy's algorithm
    bool changed = true;
    constexpr std::size_t max_iterations = 10000;
    std::size_t iteration = 0;

    while (changed && iteration++ < max_iterations) {
        changed = false;

        for (BlockId id : rpo) {
            if (id == entry_block_) continue;

            auto* block = find_block(id);
            if (!block) continue;

            const auto& preds = block->predecessors();
            if (preds.empty()) continue;

            // Find the first predecessor with a valid dominator
            BlockId new_idom = INVALID_BLOCK_ID;
            for (BlockId pred : preds) {
                auto* pred_block = find_block(pred);
                if (pred_block && pred_block->immediate_dominator() != INVALID_BLOCK_ID) {
                    new_idom = pred;
                    break;
                }
            }

            if (new_idom == INVALID_BLOCK_ID) continue;

            // Intersect dominators of all predecessors
            for (BlockId pred : preds) {
                if (pred == new_idom) continue;

                auto* pred_block = find_block(pred);
                if (!pred_block || pred_block->immediate_dominator() == INVALID_BLOCK_ID) {
                    continue;
                }

                // Intersection: walk up the dominator tree of both
                // until we find a common ancestor
                BlockId idom1 = new_idom;
                BlockId idom2 = pred;
                
                // Build path from pred to root
                std::unordered_set<BlockId> path;
                BlockId current = idom2;
                std::size_t safety = 0;
                while (current != INVALID_BLOCK_ID && current != entry_block_ && safety++ < 1000) {
                    path.insert(current);
                    auto* curr_block = find_block(current);
                    if (!curr_block) break;
                    current = curr_block->immediate_dominator();
                }
                path.insert(entry_block_);
                
                // Walk from idom1 until we hit the path
                current = idom1;
                safety = 0;
                while (current != INVALID_BLOCK_ID && safety++ < 1000) {
                    if (path.count(current)) {
                        new_idom = current;
                        break;
                    }
                    auto* curr_block = find_block(current);
                    if (!curr_block) break;
                    current = curr_block->immediate_dominator();
                }
            }

            if (new_idom != INVALID_BLOCK_ID && block->immediate_dominator() != new_idom) {
                // Safety check: don't create self-dominators or cycles
                if (new_idom != id) {
                    block->set_immediate_dominator(new_idom);
                    changed = true;
                }
            }
        }
    }
    
    if (iteration >= max_iterations) {
        spdlog::warn("Dominator computation did not converge after {} iterations for CFG with {} blocks", 
            max_iterations, blocks_.size());
    }
}

bool CFG::dominates(BlockId dominator, BlockId block) const {
    if (dominator == block) return true;

    const BasicBlock* current = find_block(block);
    std::size_t iterations = 0;
    constexpr std::size_t max_dominator_walk = 10000;
    
    while (current && current->id() != entry_block_ && iterations++ < max_dominator_walk) {
        BlockId idom = current->immediate_dominator();
        if (idom == dominator) return true;
        if (idom == INVALID_BLOCK_ID) break;
        current = find_block(idom);
    }

    return false;
}

BlockId CFG::immediate_dominator(BlockId block) const {
    const auto* b = find_block(block);
    return b ? b->immediate_dominator() : INVALID_BLOCK_ID;
}

void CFG::detect_loops() {
    loop_headers_.clear();
    loop_body_.clear();

    // Find back edges (edge to a dominator = back edge)
    for (const auto& [id, block] : blocks_) {
        for (const auto& edge : block.successors()) {
            if (dominates(edge.target, id)) {
                // Back edge found: id -> edge.target
                loop_headers_.insert(edge.target);

                // Mark the edge as back edge
                // (would need mutable access, skip for now)
            }
        }
    }

    // For each loop header, find loop body using reverse DFS
    constexpr std::size_t max_loop_iterations = 10000;
    
    for (BlockId header : loop_headers_) {
        std::vector<BlockId> body;
        body.push_back(header);

        std::stack<BlockId> worklist;

        // Find all back edge sources
        for (const auto& [id, block] : blocks_) {
            for (const auto& edge : block.successors()) {
                if (edge.target == header && dominates(header, id)) {
                    if (id != header) {
                        worklist.push(id);
                    }
                }
            }
        }

        // Reverse DFS to find loop body
        std::unordered_set<BlockId> visited;
        visited.insert(header);
        
        std::size_t iterations = 0;

        while (!worklist.empty() && iterations++ < max_loop_iterations) {
            BlockId id = worklist.top();
            worklist.pop();

            if (visited.count(id)) continue;
            visited.insert(id);
            body.push_back(id);

            const auto* block = find_block(id);
            if (block) {
                for (BlockId pred : block->predecessors()) {
                    if (!visited.count(pred)) {
                        worklist.push(pred);
                    }
                }
            }
        }
        
        if (iterations >= max_loop_iterations) {
            spdlog::warn("Loop detection exceeded max iterations ({}) for header block {} ({} blocks total)", 
                max_loop_iterations, header, blocks_.size());
        }

        loop_body_[header] = std::move(body);
    }

    // Mark loop headers
    for (BlockId header : loop_headers_) {
        if (auto* block = find_block(header)) {
            block->set_loop_header(true);
        }
    }
}

bool CFG::is_loop_header(BlockId block) const {
    return loop_headers_.count(block) > 0;
}

std::vector<BlockId> CFG::loop_blocks(BlockId header) const {
    auto it = loop_body_.find(header);
    if (it != loop_body_.end()) {
        return it->second;
    }
    return {};
}

bool CFG::is_reducible() const {
    // A CFG is reducible if all loops have a single entry point
    // Simplified check: no cross edges between loop bodies
    // Full implementation would check for irreducible loops
    return true;  // Assume reducible for now
}

std::size_t CFG::edge_count() const {
    std::size_t count = 0;
    for (const auto& [id, block] : blocks_) {
        count += block.successors().size();
    }
    return count;
}

std::size_t CFG::instruction_count() const {
    std::size_t count = 0;
    for (const auto& [id, block] : blocks_) {
        count += block.instruction_count();
    }
    return count;
}

} // namespace picanha::analysis
