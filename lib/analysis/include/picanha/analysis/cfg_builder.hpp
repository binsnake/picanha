#pragma once

#include "picanha/analysis/cfg.hpp"
#include "picanha/analysis/basic_block.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/instruction.hpp>
#include <picanha/disasm/decoder.hpp>
#include <picanha/disasm/flow_analyzer.hpp>
#include <picanha/loader/binary.hpp>
#include <memory>
#include <vector>
#include <unordered_set>
#include <functional>
#include <chrono>

namespace picanha::analysis {

// Configuration for CFG building
struct CFGBuilderConfig {
    std::size_t max_block_size{4096};
    std::size_t max_blocks{10000};
    std::size_t max_instructions{50000};   // Limit total instructions decoded
    bool split_on_call_targets{true};      // Split blocks at addresses that are call targets
    bool follow_calls{false};              // Include called functions in same CFG

    // Function bounds (if known from exception info or other source)
    Address function_start{INVALID_ADDRESS};
    Address function_end{INVALID_ADDRESS};
};

// Builds a CFG from disassembled instructions
class CFGBuilder {
public:
    explicit CFGBuilder(
        std::shared_ptr<loader::Binary> binary,
        const CFGBuilderConfig& config = {}
    );

    // Build CFG starting from an address
    [[nodiscard]] std::unique_ptr<CFG> build(Address entry_point);

    // Build CFG from pre-decoded instructions
    [[nodiscard]] std::unique_ptr<CFG> build_from_instructions(
        Address entry_point,
        const std::vector<Instruction>& instructions
    );

    // Add additional entry points (for analyzing multiple functions together)
    void add_entry_point(Address addr);

    // Set known jump/call targets (helps with block splitting)
    void add_jump_target(Address addr);
    void add_call_target(Address addr);

private:
    // Phase 1: Decode and identify block boundaries
    void decode_function(Address entry);
    void decode_function(Address entry, std::function<bool()> should_timeout);

    // Phase 2: Split instructions into basic blocks
    void create_blocks();

    // Phase 3: Add edges between blocks
    void add_edges();

    // Helper to decode at an address
    std::vector<Instruction> decode_block(Address addr);

    // Check if address is a block boundary
    bool is_block_boundary(Address addr) const;

    std::shared_ptr<loader::Binary> binary_;
    CFGBuilderConfig config_;
    disasm::Decoder decoder_;

    // Building state
    std::unique_ptr<CFG> cfg_;
    std::vector<Instruction> all_instructions_;
    std::unordered_set<Address> block_starts_;
    std::unordered_set<Address> jump_targets_;
    std::unordered_set<Address> call_targets_;
    std::unordered_set<Address> visited_;
    std::vector<Address> entry_points_;
};

} // namespace picanha::analysis
