#pragma once

#include "picanha/analysis/pattern.hpp"
#include "picanha/analysis/dag.hpp"
#include "picanha/analysis/basic_block.hpp"
#include "picanha/analysis/cfg.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/instruction.hpp>
#include <memory>
#include <vector>

namespace picanha::analysis {

// DAG builder - constructs DAG from instructions
class DAGBuilder {
public:
    DAGBuilder();

    // Build DAG from a single instruction
    void add_instruction(const Instruction& instr);

    // Build DAG from a basic block
    void add_block(const BasicBlock& block);

    // Build DAG from instruction range
    void add_instructions(const std::vector<Instruction>& instructions);

    // Get the constructed DAG
    [[nodiscard]] std::unique_ptr<DAG> take_dag();

    // Get current DAG reference
    [[nodiscard]] DAG& dag() { return *dag_; }
    [[nodiscard]] const DAG& dag() const { return *dag_; }

    // Clear and start fresh
    void reset();

private:
    // Process instruction operands
    NodeId process_operand(const Instruction& instr, int operand_index);

    // Process memory operand
    NodeId process_memory_operand(const Instruction& instr, int operand_index);

    // Get or create register node
    NodeId get_register(iced_x86::Register reg);

    // Track register definitions (SSA-like)
    void define_register(iced_x86::Register reg, NodeId value);

    // Current value of a register
    [[nodiscard]] NodeId current_register_value(iced_x86::Register reg);

    std::unique_ptr<DAG> dag_;

    // Register state tracking
    std::unordered_map<iced_x86::Register, NodeId> register_values_;
};

// Pattern matcher - finds patterns in DAGs and instruction sequences
class PatternMatcher {
public:
    explicit PatternMatcher(const PatternLibrary& library);

    // Match patterns in a DAG
    struct DAGMatchResult {
        const Pattern* pattern{nullptr};
        PatternMatch match;
        NodeId root_node{INVALID_NODE_ID};
    };

    [[nodiscard]] std::vector<DAGMatchResult> find_matches(const DAG& dag) const;

    // Match patterns in a basic block
    [[nodiscard]] std::vector<DAGMatchResult> find_matches(const BasicBlock& block) const;

    // Match specific pattern
    [[nodiscard]] std::optional<PatternMatch> match_pattern(
        const DAG& dag,
        NodeId node,
        const std::string& pattern_name
    ) const;

    // Find all jump table patterns
    struct JumpTableCandidate {
        NodeId index_node{INVALID_NODE_ID};     // Index computation
        NodeId base_node{INVALID_NODE_ID};      // Base address
        NodeId scale_node{INVALID_NODE_ID};     // Scale factor
        Address base_address{INVALID_ADDRESS};   // Resolved base
        std::uint64_t scale{0};                  // Resolved scale
        Address instruction_address{INVALID_ADDRESS};
    };

    [[nodiscard]] std::vector<JumpTableCandidate> find_jump_table_candidates(
        const DAG& dag
    ) const;

    // Find bounds check patterns (common before switch/jump tables)
    struct BoundsCheckCandidate {
        NodeId index_node{INVALID_NODE_ID};
        std::uint64_t bound{0};
        Address instruction_address{INVALID_ADDRESS};
        bool is_signed{false};
    };

    [[nodiscard]] std::vector<BoundsCheckCandidate> find_bounds_checks(
        const DAG& dag
    ) const;

private:
    const PatternLibrary& library_;
};

// Subgraph isomorphism for more complex pattern matching
class SubgraphMatcher {
public:
    // Result of subgraph matching
    struct MatchResult {
        bool matched{false};
        std::unordered_map<NodeId, NodeId> node_mapping;  // pattern -> target
    };

    // Check if pattern is a subgraph of target
    [[nodiscard]] static MatchResult match(
        const DAG& pattern,
        const DAG& target,
        NodeId pattern_root,
        NodeId target_root
    );

    // Find all occurrences of pattern in target
    [[nodiscard]] static std::vector<MatchResult> find_all(
        const DAG& pattern,
        const DAG& target
    );

private:
    // Recursive matching with backtracking
    static bool match_recursive(
        const DAG& pattern,
        const DAG& target,
        NodeId pattern_node,
        NodeId target_node,
        std::unordered_map<NodeId, NodeId>& mapping,
        std::unordered_set<NodeId>& used_target_nodes
    );
};

} // namespace picanha::analysis
