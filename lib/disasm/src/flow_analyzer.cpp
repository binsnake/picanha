#include "picanha/disasm/flow_analyzer.hpp"

namespace picanha::disasm {

std::vector<FlowTarget> FlowAnalyzer::analyze(const Instruction& instr) {
    std::vector<FlowTarget> targets;

    FlowType flow = instr.flow_type();

    switch (flow) {
        case FlowType::Sequential: {
            // Normal instruction - fallthrough only
            FlowTarget ft;
            ft.target = instr.next_ip();
            ft.is_fallthrough = true;
            targets.push_back(ft);
            break;
        }

        case FlowType::UnconditionalJump: {
            // Unconditional jump - single target
            Address target = instr.branch_target();
            if (target != INVALID_ADDRESS) {
                FlowTarget ft;
                ft.target = target;
                ft.is_conditional = false;
                targets.push_back(ft);
            }
            break;
        }

        case FlowType::ConditionalJump:
        case FlowType::Loop: {
            // Conditional - both fallthrough and taken
            FlowTarget taken;
            taken.target = instr.branch_target();
            taken.is_conditional = true;
            if (taken.target != INVALID_ADDRESS) {
                targets.push_back(taken);
            }

            FlowTarget fallthrough;
            fallthrough.target = instr.next_ip();
            fallthrough.is_fallthrough = true;
            fallthrough.is_conditional = true;
            targets.push_back(fallthrough);
            break;
        }

        case FlowType::Call: {
            // Call - target and fallthrough (return)
            Address target = instr.branch_target();
            if (target != INVALID_ADDRESS) {
                FlowTarget call_target;
                call_target.target = target;
                call_target.is_call = true;
                targets.push_back(call_target);
            }

            // Fallthrough (return address)
            FlowTarget ret;
            ret.target = instr.next_ip();
            ret.is_fallthrough = true;
            targets.push_back(ret);
            break;
        }

        case FlowType::IndirectCall: {
            // Indirect call - unknown target, but has fallthrough
            FlowTarget call_target;
            call_target.target = INVALID_ADDRESS; // Unknown
            call_target.is_call = true;
            call_target.is_indirect = true;
            targets.push_back(call_target);

            FlowTarget ret;
            ret.target = instr.next_ip();
            ret.is_fallthrough = true;
            targets.push_back(ret);
            break;
        }

        case FlowType::IndirectJump: {
            // Indirect jump - unknown target(s)
            FlowTarget ft;
            ft.target = INVALID_ADDRESS;
            ft.is_indirect = true;
            targets.push_back(ft);
            break;
        }

        case FlowType::Return:
        case FlowType::Exception:
            // No known targets
            break;

        case FlowType::Interrupt: {
            // INT instruction might return (INT 3 for debugging) or not
            // Conservatively assume it returns
            FlowTarget ft;
            ft.target = instr.next_ip();
            ft.is_fallthrough = true;
            targets.push_back(ft);
            break;
        }

        default:
            break;
    }

    return targets;
}

std::optional<Address> FlowAnalyzer::get_branch_target(const Instruction& instr) {
    if (!instr.is_branch() && !instr.is_call()) {
        return std::nullopt;
    }

    Address target = instr.branch_target();
    if (target == INVALID_ADDRESS) {
        return std::nullopt;
    }

    return target;
}

std::optional<Address> FlowAnalyzer::get_fallthrough(const Instruction& instr) {
    FlowType flow = instr.flow_type();

    switch (flow) {
        case FlowType::Sequential:
        case FlowType::ConditionalJump:
        case FlowType::Loop:
        case FlowType::Call:
        case FlowType::IndirectCall:
        case FlowType::Interrupt:
            return instr.next_ip();

        default:
            return std::nullopt;
    }
}

bool FlowAnalyzer::is_block_terminator(const Instruction& instr) {
    FlowType flow = instr.flow_type();

    switch (flow) {
        case FlowType::UnconditionalJump:
        case FlowType::ConditionalJump:
        case FlowType::IndirectJump:
        case FlowType::Return:
        case FlowType::Exception:
        case FlowType::Loop:
            return true;

        case FlowType::Call:
        case FlowType::IndirectCall:
            // Calls don't terminate blocks unless they're noreturn
            return false;

        default:
            return false;
    }
}

bool FlowAnalyzer::can_start_block(const Instruction& instr) {
    // Any valid instruction can start a block
    return instr.is_valid();
}

bool FlowAnalyzer::is_noreturn_call(const Instruction& instr) {
    // This would require symbol information to determine
    // For now, always return false
    return false;
}

bool FlowAnalyzer::could_be_tail_call(const Instruction& instr) {
    // A tail call is a JMP that could be a CALL+RET optimization
    if (instr.flow_type() != FlowType::UnconditionalJump) {
        return false;
    }

    // Indirect jumps through memory could be tail calls to imports
    if (instr.is_indirect_branch()) {
        return true;
    }

    // Direct jumps to out-of-function addresses could be tail calls
    // (Would need function bounds to determine)
    return true;
}

bool FlowAnalyzer::modifies_stack(const Instruction& instr) {
    auto mnemonic = instr.mnemonic();

    switch (mnemonic) {
        case iced_x86::Mnemonic::PUSH:
        case iced_x86::Mnemonic::POP:
        case iced_x86::Mnemonic::PUSHA:
        case iced_x86::Mnemonic::PUSHAD:
        case iced_x86::Mnemonic::POPA:
        case iced_x86::Mnemonic::POPAD:
        case iced_x86::Mnemonic::PUSHF:
        case iced_x86::Mnemonic::PUSHFD:
        case iced_x86::Mnemonic::PUSHFQ:
        case iced_x86::Mnemonic::POPF:
        case iced_x86::Mnemonic::POPFD:
        case iced_x86::Mnemonic::POPFQ:
        case iced_x86::Mnemonic::CALL:
        case iced_x86::Mnemonic::RET:
        case iced_x86::Mnemonic::ENTER:
        case iced_x86::Mnemonic::LEAVE:
            return true;

        case iced_x86::Mnemonic::ADD:
        case iced_x86::Mnemonic::SUB:
        case iced_x86::Mnemonic::LEA:
        case iced_x86::Mnemonic::MOV: {
            // Check if destination is RSP/ESP/SP
            if (instr.op_count() > 0) {
                auto dst_reg = instr.op_register(0);
                if (dst_reg == iced_x86::Register::RSP ||
                    dst_reg == iced_x86::Register::ESP ||
                    dst_reg == iced_x86::Register::SP) {
                    return true;
                }
            }
            return false;
        }

        default:
            return false;
    }
}

std::optional<std::int32_t> FlowAnalyzer::get_stack_delta(const Instruction& instr) {
    auto mnemonic = instr.mnemonic();

    switch (mnemonic) {
        case iced_x86::Mnemonic::PUSH:
            return 8; // 64-bit push

        case iced_x86::Mnemonic::POP:
            return -8;

        case iced_x86::Mnemonic::CALL:
            return 8; // Pushes return address

        case iced_x86::Mnemonic::RET:
            return -8; // Pops return address

        case iced_x86::Mnemonic::SUB: {
            // SUB RSP, imm
            if (instr.op_count() >= 2) {
                auto dst = instr.op_register(0);
                if (dst == iced_x86::Register::RSP || dst == iced_x86::Register::ESP) {
                    auto kind = instr.op_kind(1);
                    if (kind == iced_x86::OpKind::IMMEDIATE8 ||
                        kind == iced_x86::OpKind::IMMEDIATE8TO32 ||
                        kind == iced_x86::OpKind::IMMEDIATE8TO64 ||
                        kind == iced_x86::OpKind::IMMEDIATE16 ||
                        kind == iced_x86::OpKind::IMMEDIATE32 ||
                        kind == iced_x86::OpKind::IMMEDIATE32TO64 ||
                        kind == iced_x86::OpKind::IMMEDIATE64) {
                        return static_cast<std::int32_t>(instr.get_immediate_for_operand(1));
                    }
                }
            }
            break;
        }

        case iced_x86::Mnemonic::ADD: {
            // ADD RSP, imm
            if (instr.op_count() >= 2) {
                auto dst = instr.op_register(0);
                if (dst == iced_x86::Register::RSP || dst == iced_x86::Register::ESP) {
                    auto kind = instr.op_kind(1);
                    if (kind == iced_x86::OpKind::IMMEDIATE8 ||
                        kind == iced_x86::OpKind::IMMEDIATE8TO32 ||
                        kind == iced_x86::OpKind::IMMEDIATE8TO64 ||
                        kind == iced_x86::OpKind::IMMEDIATE16 ||
                        kind == iced_x86::OpKind::IMMEDIATE32 ||
                        kind == iced_x86::OpKind::IMMEDIATE32TO64 ||
                        kind == iced_x86::OpKind::IMMEDIATE64) {
                        return -static_cast<std::int32_t>(instr.get_immediate_for_operand(1));
                    }
                }
            }
            break;
        }

        default:
            break;
    }

    return std::nullopt;
}

} // namespace picanha::disasm
