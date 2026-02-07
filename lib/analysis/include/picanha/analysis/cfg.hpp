#pragma once

#include "picanha/analysis/basic_block.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/parallel.hpp>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <optional>
#include <functional>

namespace picanha::analysis {

// Control Flow Graph
class CFG {
public:
    CFG() = default;

    // Block management
    BasicBlock& create_block(Address start_address);
    BasicBlock& get_block(BlockId id);
    const BasicBlock& get_block(BlockId id) const;
    BasicBlock* find_block(BlockId id);
    const BasicBlock* find_block(BlockId id) const;

    // Find block containing address
    BasicBlock* find_block_at(Address addr);
    const BasicBlock* find_block_at(Address addr) const;

    // Find block starting at address
    BasicBlock* find_block_starting_at(Address addr);
    const BasicBlock* find_block_starting_at(Address addr) const;

    // Block iteration
    [[nodiscard]] std::size_t block_count() const noexcept { return blocks_.size(); }

    template<typename Func>
    void for_each_block(Func&& func) {
        for (auto& [id, block] : blocks_) {
            func(block);
        }
    }

    template<typename Func>
    void for_each_block(Func&& func) const {
        for (const auto& [id, block] : blocks_) {
            func(block);
        }
    }

    // Get all blocks (for algorithms that need random access)
    [[nodiscard]] std::vector<BasicBlock*> get_all_blocks();
    [[nodiscard]] std::vector<const BasicBlock*> get_all_blocks() const;

    // Edge management
    void add_edge(BlockId from, BlockId to, EdgeType type);
    void add_edge(BasicBlock& from, BasicBlock& to, EdgeType type);

    // Entry/exit blocks
    void set_entry_block(BlockId id);
    [[nodiscard]] BlockId entry_block_id() const noexcept { return entry_block_; }
    [[nodiscard]] BasicBlock* entry_block();
    [[nodiscard]] const BasicBlock* entry_block() const;

    [[nodiscard]] const std::vector<BlockId>& exit_blocks() const noexcept {
        return exit_blocks_;
    }

    void add_exit_block(BlockId id);

    // Graph properties
    [[nodiscard]] bool is_empty() const noexcept { return blocks_.empty(); }
    [[nodiscard]] bool is_reducible() const;  // No irreducible loops

    // Traversal
    using BlockVisitor = std::function<void(BasicBlock&)>;
    using ConstBlockVisitor = std::function<void(const BasicBlock&)>;

    void dfs_preorder(BlockVisitor visitor);
    void dfs_postorder(BlockVisitor visitor);
    void bfs(BlockVisitor visitor);

    void dfs_preorder(ConstBlockVisitor visitor) const;
    void dfs_postorder(ConstBlockVisitor visitor) const;
    void bfs(ConstBlockVisitor visitor) const;

    // Reverse postorder (useful for dataflow)
    [[nodiscard]] std::vector<BlockId> reverse_postorder() const;

    // Dominance
    void compute_dominators();
    [[nodiscard]] bool dominates(BlockId dominator, BlockId block) const;
    [[nodiscard]] BlockId immediate_dominator(BlockId block) const;

    // Loop detection
    void detect_loops();
    [[nodiscard]] bool is_loop_header(BlockId block) const;
    [[nodiscard]] std::vector<BlockId> loop_blocks(BlockId header) const;
    [[nodiscard]] const std::unordered_set<BlockId>& loop_headers() const noexcept {
        return loop_headers_;
    }

    // Statistics
    [[nodiscard]] std::size_t edge_count() const;
    [[nodiscard]] std::size_t instruction_count() const;

private:
    void dfs_preorder_impl(BlockId id, BlockVisitor& visitor,
                           std::unordered_set<BlockId>& visited);
    void dfs_postorder_impl(BlockId id, BlockVisitor& visitor,
                            std::unordered_set<BlockId>& visited);

    std::unordered_map<BlockId, BasicBlock> blocks_;
    std::unordered_map<Address, BlockId> address_to_block_;

    BlockId entry_block_{INVALID_BLOCK_ID};
    std::vector<BlockId> exit_blocks_;

    BlockId next_block_id_{0};

    // Loop info
    std::unordered_set<BlockId> loop_headers_;
    std::unordered_map<BlockId, std::vector<BlockId>> loop_body_;
};

} // namespace picanha::analysis
