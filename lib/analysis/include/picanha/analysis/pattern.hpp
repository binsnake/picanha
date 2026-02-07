#pragma once

#include "picanha/analysis/dag.hpp"
#include <picanha/core/types.hpp>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <unordered_map>

namespace picanha::analysis {

// Pattern constraint types
enum class PatternConstraint : std::uint8_t {
    None,
    IsConstant,         // Must be a constant
    IsRegister,         // Must be a register
    IsMemory,           // Must be a memory reference
    IsPowerOf2,         // Constant must be power of 2
    IsInRange,          // Constant in specific range
    MatchesRegClass,    // Register matches class
    HasBitWidth,        // Specific bit width
};

// A constraint on a pattern node
struct PatternNodeConstraint {
    PatternConstraint type{PatternConstraint::None};
    std::uint64_t value1{0};    // For ranges: min
    std::uint64_t value2{0};    // For ranges: max
    std::string reg_class;       // For register class matching
};

// Pattern node - template for matching DAG structures
struct PatternNode {
    std::string name;                   // Capture name (empty = don't capture)
    DAGOp op{DAGOp::Unknown};           // Operation (Unknown = wildcard)
    std::vector<std::size_t> children;  // Indices of child patterns
    std::vector<PatternNodeConstraint> constraints;

    // For leaf nodes
    bool is_wildcard{false};            // Match any node
    bool is_constant_wildcard{false};   // Match any constant
    bool is_register_wildcard{false};   // Match any register

    [[nodiscard]] bool has_capture() const { return !name.empty(); }
};

// Result of pattern matching - captured values
struct PatternMatch {
    bool matched{false};
    std::unordered_map<std::string, NodeId> captures;

    // Get captured constant value
    [[nodiscard]] std::optional<std::uint64_t> get_constant(
        const std::string& name,
        const DAG& dag
    ) const;

    // Get captured register
    [[nodiscard]] std::optional<iced_x86::Register> get_register(
        const std::string& name,
        const DAG& dag
    ) const;

    // Get captured node
    [[nodiscard]] NodeId get_node(const std::string& name) const;
};

// Pattern definition
class Pattern {
public:
    Pattern() = default;
    explicit Pattern(std::string name);

    // Build pattern tree
    std::size_t add_node(PatternNode node);
    void set_root(std::size_t index) { root_ = index; }

    // Pattern info
    [[nodiscard]] const std::string& name() const noexcept { return name_; }
    [[nodiscard]] std::size_t node_count() const noexcept { return nodes_.size(); }
    [[nodiscard]] std::size_t root() const noexcept { return root_; }

    // Node access
    [[nodiscard]] const PatternNode& get_node(std::size_t index) const;

    // Match against DAG
    [[nodiscard]] PatternMatch match(const DAG& dag, NodeId node) const;

    // Builder helpers for common patterns
    static Pattern jump_table_load();      // load(base + index * scale)
    static Pattern scaled_index();         // index * scale
    static Pattern base_plus_offset();     // base + offset
    static Pattern compare_and_branch();   // if (x < n) goto ...
    static Pattern bounds_check();         // if (x >= n) goto default

private:
    bool match_node(
        const DAG& dag,
        NodeId dag_node,
        std::size_t pattern_node,
        PatternMatch& result
    ) const;

    bool check_constraints(
        const DAG& dag,
        NodeId dag_node,
        const PatternNode& pattern_node
    ) const;

    std::string name_;
    std::vector<PatternNode> nodes_;
    std::size_t root_{0};
};

// Pattern library - collection of named patterns
class PatternLibrary {
public:
    PatternLibrary();

    // Add pattern
    void add(Pattern pattern);

    // Get pattern by name
    [[nodiscard]] const Pattern* find(const std::string& name) const;

    // Match all patterns against a node
    [[nodiscard]] std::vector<std::pair<const Pattern*, PatternMatch>>
    match_all(const DAG& dag, NodeId node) const;

    // Iteration
    [[nodiscard]] const std::vector<Pattern>& patterns() const noexcept {
        return patterns_;
    }

private:
    std::vector<Pattern> patterns_;
    std::unordered_map<std::string, std::size_t> name_to_index_;
};

// Global pattern library with common patterns
[[nodiscard]] const PatternLibrary& builtin_patterns();

} // namespace picanha::analysis
