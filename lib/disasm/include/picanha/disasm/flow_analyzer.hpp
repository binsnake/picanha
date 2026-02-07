#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/instruction.hpp>
#include <vector>
#include <optional>

namespace picanha::disasm {

// Represents a possible execution path from an instruction
struct FlowTarget {
    Address target{INVALID_ADDRESS};
    bool is_conditional{false};
    bool is_call{false};
    bool is_indirect{false};
    bool is_fallthrough{false};

    [[nodiscard]] bool is_valid() const noexcept {
        return target != INVALID_ADDRESS;
    }
};

// Analyzes control flow from instructions
class FlowAnalyzer {
public:
    // Get all possible targets from an instruction
    [[nodiscard]] static std::vector<FlowTarget> analyze(const Instruction& instr);

    // Get branch target (direct jumps/calls only)
    [[nodiscard]] static std::optional<Address> get_branch_target(const Instruction& instr);

    // Get fallthrough address (for conditional branches and sequential flow)
    [[nodiscard]] static std::optional<Address> get_fallthrough(const Instruction& instr);

    // Check if instruction terminates a basic block
    [[nodiscard]] static bool is_block_terminator(const Instruction& instr);

    // Check if instruction can start a basic block
    [[nodiscard]] static bool can_start_block(const Instruction& instr);

    // Check if this is a "no-return" call (calls to functions that don't return)
    // Note: This requires symbol information, returns false by default
    [[nodiscard]] static bool is_noreturn_call(const Instruction& instr);

    // Check if this looks like a tail call (jmp instead of call at function end)
    [[nodiscard]] static bool could_be_tail_call(const Instruction& instr);

    // Check if instruction modifies stack pointer
    [[nodiscard]] static bool modifies_stack(const Instruction& instr);

    // Get stack delta (positive = push/sub rsp, negative = pop/add rsp)
    [[nodiscard]] static std::optional<std::int32_t> get_stack_delta(const Instruction& instr);
};

} // namespace picanha::disasm
