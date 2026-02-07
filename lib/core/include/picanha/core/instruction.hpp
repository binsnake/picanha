#pragma once

#include "picanha/core/types.hpp"
#include <iced_x86/iced_x86.hpp>
#include <iced_x86/instruction_info.hpp>
#include <string>
#include <string_view>

namespace picanha {

// Flow control classification
enum class FlowType : std::uint8_t {
    Sequential,         // Falls through to next instruction
    UnconditionalJump,  // JMP
    ConditionalJump,    // Jcc (JZ, JNZ, etc.)
    Call,               // CALL
    IndirectCall,       // CALL reg/mem
    IndirectJump,       // JMP reg/mem
    Return,             // RET, IRET
    Interrupt,          // INT, SYSCALL
    Exception,          // UD2, etc.
    Loop,               // LOOP, LOOPE, LOOPNE
    Unknown
};

// Thin wrapper over iced_x86::Instruction with additional metadata
class Instruction {
public:
    Instruction() = default;

    explicit Instruction(const iced_x86::Instruction& instr)
        : instr_(instr) {}

    Instruction(const iced_x86::Instruction& instr, Address ip)
        : instr_(instr) {
        // IP is already set in iced instruction
    }

    // Basic properties
    [[nodiscard]] Address ip() const noexcept { return instr_.ip(); }
    [[nodiscard]] std::uint8_t length() const noexcept { return static_cast<std::uint8_t>(instr_.length()); }
    [[nodiscard]] Address next_ip() const noexcept { return ip() + length(); }
    [[nodiscard]] bool is_valid() const noexcept { return instr_.code() != iced_x86::Code::INVALID; }

    // Mnemonic and code
    [[nodiscard]] iced_x86::Mnemonic mnemonic() const noexcept { return instr_.mnemonic(); }
    [[nodiscard]] iced_x86::Code code() const noexcept { return instr_.code(); }

    // Operand access
    [[nodiscard]] std::uint32_t op_count() const noexcept { return instr_.op_count(); }
    [[nodiscard]] iced_x86::OpKind op_kind(std::uint32_t index) const noexcept {
        return instr_.op_kind(index);
    }
    [[nodiscard]] iced_x86::Register op_register(std::uint32_t index) const noexcept {
        return instr_.op_register(index);
    }

    // Memory operand details
    [[nodiscard]] iced_x86::Register memory_base() const noexcept { return instr_.memory_base(); }
    [[nodiscard]] iced_x86::Register memory_index() const noexcept { return instr_.memory_index(); }
    [[nodiscard]] std::uint32_t memory_index_scale() const noexcept { return instr_.memory_index_scale(); }
    [[nodiscard]] std::int64_t memory_displacement() const noexcept {
        return static_cast<std::int64_t>(instr_.memory_displacement64());
    }
    [[nodiscard]] iced_x86::MemorySize memory_size() const noexcept { return instr_.memory_size_enum(); }

    // Immediate values
    [[nodiscard]] std::uint64_t immediate64() const noexcept {
        return instr_.immediate64();
    }

    [[nodiscard]] std::uint32_t immediate32() const noexcept {
        return instr_.immediate32();
    }

    [[nodiscard]] std::uint8_t immediate8() const noexcept {
        return instr_.immediate8();
    }

    [[nodiscard]] std::int32_t immediate8to32() const noexcept {
        return instr_.immediate8to32();
    }

    // Get immediate value based on operand kind (helper for analysis)
    [[nodiscard]] std::int64_t get_immediate_for_operand(std::uint32_t operand_index) const noexcept {
        auto kind = op_kind(operand_index);
        switch (kind) {
            case iced_x86::OpKind::IMMEDIATE8:
                return instr_.immediate8to64();
            case iced_x86::OpKind::IMMEDIATE16:
                return instr_.immediate16();
            case iced_x86::OpKind::IMMEDIATE32:
                return instr_.immediate32();
            case iced_x86::OpKind::IMMEDIATE64:
                return static_cast<std::int64_t>(instr_.immediate64());
            case iced_x86::OpKind::IMMEDIATE8TO16:
                return instr_.immediate8to16();
            case iced_x86::OpKind::IMMEDIATE8TO32:
                return instr_.immediate8to32();
            case iced_x86::OpKind::IMMEDIATE8TO64:
                return instr_.immediate8to64();
            case iced_x86::OpKind::IMMEDIATE32TO64:
                return instr_.immediate32to64();
            default:
                return 0;
        }
    }

    // Branch target
    [[nodiscard]] Address near_branch_target() const noexcept {
        return instr_.near_branch_target();
    }
    [[nodiscard]] Address far_branch_selector() const noexcept {
        return instr_.far_branch_selector();
    }

    // Flow control analysis
    [[nodiscard]] FlowType flow_type() const noexcept {
        auto fc = iced_x86::InstructionExtensions::flow_control(instr_);
        switch (fc) {
            case iced_x86::FlowControl::NEXT:
                return FlowType::Sequential;
            case iced_x86::FlowControl::UNCONDITIONAL_BRANCH:
                if (is_indirect_branch()) {
                    return FlowType::IndirectJump;
                }
                return FlowType::UnconditionalJump;
            case iced_x86::FlowControl::CONDITIONAL_BRANCH:
                return FlowType::ConditionalJump;
            case iced_x86::FlowControl::CALL:
                if (is_indirect_branch()) {
                    return FlowType::IndirectCall;
                }
                return FlowType::Call;
            case iced_x86::FlowControl::INDIRECT_CALL:
                return FlowType::IndirectCall;
            case iced_x86::FlowControl::INDIRECT_BRANCH:
                return FlowType::IndirectJump;
            case iced_x86::FlowControl::RETURN:
                return FlowType::Return;
            case iced_x86::FlowControl::INTERRUPT:
                return FlowType::Interrupt;
            case iced_x86::FlowControl::EXCEPTION:
                return FlowType::Exception;
            case iced_x86::FlowControl::XBEGIN_XABORT_XEND:
                return FlowType::Unknown;
            default:
                return FlowType::Unknown;
        }
    }

    // Flow control helpers
    [[nodiscard]] bool is_branch() const noexcept {
        auto ft = flow_type();
        return ft == FlowType::UnconditionalJump ||
               ft == FlowType::ConditionalJump ||
               ft == FlowType::IndirectJump;
    }

    [[nodiscard]] bool is_call() const noexcept {
        auto ft = flow_type();
        return ft == FlowType::Call || ft == FlowType::IndirectCall;
    }

    [[nodiscard]] bool is_return() const noexcept {
        return flow_type() == FlowType::Return;
    }

    [[nodiscard]] bool is_terminator() const noexcept {
        auto ft = flow_type();
        return ft != FlowType::Sequential && ft != FlowType::Call;
    }

    [[nodiscard]] bool is_conditional() const noexcept {
        return flow_type() == FlowType::ConditionalJump ||
               flow_type() == FlowType::Loop;
    }

    [[nodiscard]] bool is_indirect_branch() const noexcept {
        if (op_count() == 0) return false;
        auto kind = op_kind(0);
        return kind == iced_x86::OpKind::REGISTER ||
               kind == iced_x86::OpKind::MEMORY;
    }

    // Compute memory address for RIP-relative addressing
    [[nodiscard]] Address compute_rip_relative_address() const noexcept {
        if (memory_base() == iced_x86::Register::RIP) {
            return next_ip() + memory_displacement();
        }
        return INVALID_ADDRESS;
    }

    // Compute absolute branch target
    [[nodiscard]] Address branch_target() const noexcept {
        auto ft = flow_type();
        if (ft == FlowType::IndirectJump || ft == FlowType::IndirectCall) {
            // Check for RIP-relative
            auto addr = compute_rip_relative_address();
            if (addr != INVALID_ADDRESS) {
                return addr;
            }
            return INVALID_ADDRESS; // Need runtime resolution
        }

        if (is_branch() || is_call()) {
            return near_branch_target();
        }

        return INVALID_ADDRESS;
    }

    // Access underlying iced instruction
    [[nodiscard]] const iced_x86::Instruction& raw() const noexcept { return instr_; }
    [[nodiscard]] iced_x86::Instruction& raw() noexcept { return instr_; }

    // Formatting (uses fast formatter internally)
    [[nodiscard]] std::string to_string() const;

private:
    iced_x86::Instruction instr_;
};

// Format instruction to string (defined in instruction.cpp)
inline std::string Instruction::to_string() const {
    iced_x86::FastStringOutput output;
    iced_x86::FastFormatter formatter;
    formatter.format(instr_, output);
    return std::string(output.view());
}

} // namespace picanha
