#pragma once

#include "picanha/analysis/jump_table.hpp"
#include "picanha/analysis/cfg.hpp"
#include "picanha/analysis/function.hpp"
#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>
#include <memory>
#include <vector>
#include <optional>

namespace picanha::analysis {

// A single switch case
struct SwitchCase {
    std::int64_t value;                 // Case value
    Address target{INVALID_ADDRESS};    // Target address
    BlockId target_block{INVALID_BLOCK_ID};
    bool is_default{false};
    bool is_fallthrough{false};         // Falls through to next case

    // Range cases (case 1 ... 5:)
    bool is_range{false};
    std::int64_t range_end{0};
};

// Represents a reconstructed switch statement
struct SwitchStatement {
    Address address{INVALID_ADDRESS};       // Address of switch (typically the jump)
    Address index_address{INVALID_ADDRESS}; // Where index is computed

    // Cases
    std::vector<SwitchCase> cases;
    std::optional<SwitchCase> default_case;

    // Bounds
    std::int64_t min_value{0};
    std::int64_t max_value{0};
    bool is_signed{false};

    // Associated jump table (if found)
    const JumpTable* jump_table{nullptr};

    // Quality
    std::uint8_t confidence{0};
    bool is_complete{false};            // All cases resolved

    [[nodiscard]] std::size_t case_count() const noexcept {
        return cases.size();
    }

    [[nodiscard]] bool has_default() const noexcept {
        return default_case.has_value();
    }

    // Find case by value
    [[nodiscard]] const SwitchCase* find_case(std::int64_t value) const;

    // Find case by target
    [[nodiscard]] const SwitchCase* find_case_by_target(Address target) const;
};

// Configuration for switch analysis
struct SwitchAnalyzerConfig {
    bool detect_cascaded_ifs{true};     // Detect if-else chains as switches
    bool detect_binary_search{true};    // Detect binary search switch impl
    bool merge_adjacent_cases{true};    // Merge cases with same target
    std::size_t max_cases{4096};
    std::int64_t max_value_gap{1000};   // Max gap between consecutive case values
};

// Switch statement analyzer
class SwitchAnalyzer {
public:
    SwitchAnalyzer(
        std::shared_ptr<loader::Binary> binary,
        const SwitchAnalyzerConfig& config = {}
    );

    // Analyze a function for switch statements
    [[nodiscard]] std::vector<SwitchStatement> analyze_function(
        const Function& function
    );

    // Analyze a function's CFG
    [[nodiscard]] std::vector<SwitchStatement> analyze_cfg(
        const CFG& cfg
    );

    // Convert jump table to switch statement
    [[nodiscard]] SwitchStatement from_jump_table(
        const JumpTable& table,
        const CFG& cfg
    );

    // Detect if-else chain that could be a switch
    [[nodiscard]] std::optional<SwitchStatement> detect_if_chain(
        const CFG& cfg,
        BlockId start_block
    );

    // Get jump table analyzer
    [[nodiscard]] JumpTableAnalyzer& jump_table_analyzer() {
        return jt_analyzer_;
    }

private:
    // Find default case from bounds check
    [[nodiscard]] std::optional<SwitchCase> find_default_case(
        const CFG& cfg,
        Address jump_address,
        const JumpTable& table
    );

    // Merge cases with same target
    void merge_cases(SwitchStatement& sw);

    // Detect if block is a comparison for switch
    struct ComparisonInfo {
        std::int64_t value;
        Address true_target;
        Address false_target;
        bool found{false};
    };

    [[nodiscard]] ComparisonInfo analyze_comparison_block(const BasicBlock& block);

    std::shared_ptr<loader::Binary> binary_;
    SwitchAnalyzerConfig config_;
    JumpTableAnalyzer jt_analyzer_;
};

// Utility: classify switch implementation style
enum class SwitchStyle {
    JumpTable,          // Direct jump table
    RelativeJumpTable,  // Table of relative offsets
    IfElseChain,        // Cascaded if-else
    BinarySearch,       // Binary search tree
    Mixed,              // Combination
    Unknown,
};

[[nodiscard]] SwitchStyle classify_switch(const SwitchStatement& sw);
[[nodiscard]] const char* switch_style_name(SwitchStyle style);

} // namespace picanha::analysis
