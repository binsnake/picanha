#pragma once

#include "picanha/analysis/dag.hpp"
#include "picanha/analysis/pattern_matcher.hpp"
#include "picanha/analysis/cfg.hpp"
#include "picanha/analysis/basic_block.hpp"
#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>
#include <memory>
#include <vector>
#include <optional>

namespace picanha::analysis {

// Jump table entry type
enum class JumpTableEntryType : std::uint8_t {
    Absolute,       // Full absolute address
    Relative32,     // 32-bit relative offset from table base
    Relative16,     // 16-bit relative offset
    Relative8,      // 8-bit relative offset
    Index8,         // 8-bit index into another table
};

// Represents a discovered jump table
struct JumpTable {
    Address table_address{INVALID_ADDRESS};     // Address of the jump table
    Address instruction_address{INVALID_ADDRESS}; // Address of the indirect jump
    Address base_address{INVALID_ADDRESS};      // Base for relative offsets

    std::size_t entry_count{0};
    std::size_t entry_size{0};                  // Size of each entry in bytes
    JumpTableEntryType entry_type{JumpTableEntryType::Absolute};

    std::vector<Address> targets;               // Resolved target addresses
    std::optional<std::size_t> default_case;    // Index of default case (if detected)

    // Bounds check info
    Address bounds_check_addr{INVALID_ADDRESS};
    std::uint64_t max_index{0};

    // Quality metrics
    std::uint8_t confidence{0};                 // 0-100
    bool all_targets_valid{false};

    [[nodiscard]] bool is_valid() const noexcept {
        return table_address != INVALID_ADDRESS &&
               entry_count > 0 &&
               !targets.empty();
    }

    [[nodiscard]] Size size() const noexcept {
        return entry_count * entry_size;
    }
};

// Configuration for jump table analysis
struct JumpTableConfig {
    std::size_t max_entries{1024};              // Max entries to consider
    std::size_t min_entries{2};                 // Min entries for valid table
    bool require_bounds_check{false};           // Require cmp/ja pattern
    bool allow_relative_tables{true};           // Allow relative offset tables
    bool follow_default_case{true};             // Try to identify default case
};

// Jump table analyzer - finds and resolves jump tables
class JumpTableAnalyzer {
public:
    JumpTableAnalyzer(
        std::shared_ptr<loader::Binary> binary,
        const JumpTableConfig& config = {}
    );

    // Analyze a single indirect jump
    [[nodiscard]] std::optional<JumpTable> analyze_indirect_jump(
        const BasicBlock& block,
        Address jump_address
    );

    // Analyze a function's CFG for jump tables
    [[nodiscard]] std::vector<JumpTable> analyze_function(const CFG& cfg);

    // Try to resolve jump table from known table address
    [[nodiscard]] std::optional<JumpTable> resolve_table(
        Address table_address,
        Address base_address,
        std::size_t entry_size,
        JumpTableEntryType entry_type,
        std::size_t max_entries = 0
    );

    // Validate if addresses are valid code targets
    [[nodiscard]] bool validate_targets(const std::vector<Address>& targets) const;

private:
    // Analyze instruction sequence for jump table pattern
    [[nodiscard]] std::optional<JumpTable> analyze_pattern(
        const std::vector<Instruction>& instructions,
        std::size_t jump_index
    );

    // Try different table types
    [[nodiscard]] std::optional<JumpTable> try_absolute_table(
        Address table_addr,
        std::size_t entry_size
    );

    [[nodiscard]] std::optional<JumpTable> try_relative_table(
        Address table_addr,
        Address base_addr,
        std::size_t entry_size,
        bool is_signed
    );

    // Read table entries
    [[nodiscard]] std::vector<Address> read_absolute_entries(
        Address table_addr,
        std::size_t entry_size,
        std::size_t count
    );

    [[nodiscard]] std::vector<Address> read_relative_entries(
        Address table_addr,
        Address base_addr,
        std::size_t entry_size,
        std::size_t count,
        bool is_signed
    );

    // Find bounds check before jump
    struct BoundsCheckInfo {
        Address address{INVALID_ADDRESS};
        std::uint64_t bound{0};
        bool found{false};
    };

    [[nodiscard]] BoundsCheckInfo find_bounds_check(
        const std::vector<Instruction>& instructions,
        std::size_t jump_index
    );

    std::shared_ptr<loader::Binary> binary_;
    JumpTableConfig config_;
    PatternMatcher matcher_;
};

// Utility functions
[[nodiscard]] const char* jump_table_entry_type_name(JumpTableEntryType type);

} // namespace picanha::analysis
