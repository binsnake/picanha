#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/instruction.hpp>
#include <cstdint>
#include <vector>
#include <span>

namespace picanha::disasm {

// Extended instruction information for analysis
struct InstructionInfo {
    Instruction instruction;

    // Location
    Address address{INVALID_ADDRESS};
    BlockId block_id{INVALID_BLOCK_ID};
    FunctionId function_id{INVALID_FUNCTION_ID};

    // Flags
    bool is_entry_point{false};        // Function entry
    bool is_block_start{false};        // Basic block start
    bool is_block_end{false};          // Basic block end
    bool is_call_target{false};        // Called from somewhere
    bool is_jump_target{false};        // Jumped to
    bool has_xrefs_to{false};          // Has incoming references
    bool has_xrefs_from{false};        // Has outgoing references
    bool is_in_delay_slot{false};      // In branch delay slot (not used on x86)
    bool is_data{false};               // Actually data, not code
    bool is_padding{false};            // NOP padding
    bool is_thunk{false};              // JMP to import (thunk)

    // Analysis state
    enum class State : std::uint8_t {
        Unknown,
        Queued,
        Decoded,
        Analyzed,
        Complete
    };
    State state{State::Unknown};

    [[nodiscard]] bool is_valid() const noexcept {
        return address != INVALID_ADDRESS && instruction.is_valid();
    }

    [[nodiscard]] Address next_address() const noexcept {
        return address + instruction.length();
    }
};

// Compact instruction storage for basic blocks
struct CompactInstruction {
    std::uint32_t offset_from_block_start;  // Offset within block
    std::uint8_t length;                     // Instruction length
    FlowType flow_type;                      // Flow control type
    std::uint8_t flags;                      // Packed flags

    // Flags
    static constexpr std::uint8_t FLAG_IS_CALL = 1 << 0;
    static constexpr std::uint8_t FLAG_IS_INDIRECT = 1 << 1;
    static constexpr std::uint8_t FLAG_HAS_RELOC = 1 << 2;
    static constexpr std::uint8_t FLAG_IS_THUNK = 1 << 3;

    [[nodiscard]] bool is_call() const noexcept { return flags & FLAG_IS_CALL; }
    [[nodiscard]] bool is_indirect() const noexcept { return flags & FLAG_IS_INDIRECT; }
    [[nodiscard]] bool has_reloc() const noexcept { return flags & FLAG_HAS_RELOC; }
    [[nodiscard]] bool is_thunk() const noexcept { return flags & FLAG_IS_THUNK; }
};

} // namespace picanha::disasm
