#include "picanha/analysis/jump_table.hpp"
#include <picanha/disasm/flow_analyzer.hpp>
#include <algorithm>
#include <cstring>

namespace picanha::analysis {

JumpTableAnalyzer::JumpTableAnalyzer(
    std::shared_ptr<loader::Binary> binary,
    const JumpTableConfig& config
)
    : binary_(std::move(binary))
    , config_(config)
    , matcher_(builtin_patterns())
{}

std::optional<JumpTable> JumpTableAnalyzer::analyze_indirect_jump(
    const BasicBlock& block,
    Address jump_address
) {
    // Find the jump instruction in the block
    std::size_t jump_index = 0;
    bool found = false;

    const auto& instructions = block.instructions();
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        if (instructions[i].ip() == jump_address) {
            jump_index = i;
            found = true;
            break;
        }
    }

    if (!found) return std::nullopt;

    return analyze_pattern(instructions, jump_index);
}

std::vector<JumpTable> JumpTableAnalyzer::analyze_function(const CFG& cfg) {
    std::vector<JumpTable> results;

    cfg.for_each_block([&](const BasicBlock& block) {
        // Check if block ends with indirect jump
        const auto* last = block.last_instruction();
        if (!last) return;

        if (last->flow_type() == FlowType::IndirectJump) {
            if (auto table = analyze_indirect_jump(block, last->ip())) {
                results.push_back(std::move(*table));
            }
        }
    });

    return results;
}

std::optional<JumpTable> JumpTableAnalyzer::analyze_pattern(
    const std::vector<Instruction>& instructions,
    std::size_t jump_index
) {
    if (jump_index >= instructions.size()) return std::nullopt;

    const auto& jump_instr = instructions[jump_index];
    const auto& underlying = jump_instr.raw();

    // Check if it's jmp [reg] or jmp [mem]
    if (underlying.op_count() < 1) return std::nullopt;

    auto op_kind = underlying.op_kind(0);
    if (op_kind != iced_x86::OpKind::MEMORY && op_kind != iced_x86::OpKind::REGISTER) {
        return std::nullopt;
    }

    // Build DAG from instructions leading up to the jump
    DAGBuilder builder;
    std::size_t start_idx = jump_index > 20 ? jump_index - 20 : 0;
    for (std::size_t i = start_idx; i <= jump_index; ++i) {
        builder.add_instruction(instructions[i]);
    }

    auto& dag = builder.dag();

    // Look for jump table candidates
    auto candidates = matcher_.find_jump_table_candidates(dag);

    // Also look for bounds checks
    auto bounds_checks = matcher_.find_bounds_checks(dag);

    // Find bounds check that matches our pattern
    BoundsCheckInfo bounds_info = find_bounds_check(instructions, jump_index);

    // Try to resolve table from memory operand
    if (op_kind == iced_x86::OpKind::MEMORY) {
        auto base_reg = underlying.memory_base();
        auto index_reg = underlying.memory_index();
        auto scale = underlying.memory_index_scale();
        auto displacement = underlying.memory_displacement64();

        // Pattern 1: jmp [table + index * scale]
        if (base_reg == iced_x86::Register::NONE && index_reg != iced_x86::Register::NONE) {
            // Table address is displacement, index in register
            if (displacement != 0) {
                std::size_t entry_size = scale > 0 ? scale : 8;
                std::size_t max_entries = bounds_info.found ? bounds_info.bound : config_.max_entries;

                if (auto table = try_absolute_table(displacement, entry_size)) {
                    table->instruction_address = jump_instr.ip();
                    table->entry_count = std::min(table->targets.size(), max_entries);
                    table->targets.resize(table->entry_count);

                    if (bounds_info.found) {
                        table->bounds_check_addr = bounds_info.address;
                        table->max_index = bounds_info.bound;
                        table->confidence = 90;
                    } else {
                        table->confidence = 70;
                    }

                    return table;
                }
            }
        }

        // Pattern 2: jmp [base + index * scale] where base contains table address
        // Need to track where base register was loaded from

        // Pattern 3: jmp [rip + displacement] with computed target
        if (base_reg == iced_x86::Register::RIP) {
            Address target_addr = jump_instr.next_ip() + displacement;

            // This could be loading from a jump table
            // Need more context to determine
        }
    }

    // Pattern 4: jmp reg where reg was loaded from table
    if (op_kind == iced_x86::OpKind::REGISTER) {
        // Look backward for: mov reg, [table + index * scale]
        for (std::size_t i = jump_index; i > 0 && i > jump_index - 10; --i) {
            const auto& instr = instructions[i - 1];
            const auto& u = instr.raw();

            if (u.mnemonic() == iced_x86::Mnemonic::MOV &&
                u.op_count() >= 2 &&
                u.op_kind(0) == iced_x86::OpKind::REGISTER &&
                u.op_register(0) == underlying.op_register(0) &&
                u.op_kind(1) == iced_x86::OpKind::MEMORY) {

                auto disp = u.memory_displacement64();
                auto idx_reg = u.memory_index();
                auto scale = u.memory_index_scale();

                if (idx_reg != iced_x86::Register::NONE && disp != 0) {
                    std::size_t entry_size = scale > 0 ? scale : 8;
                    std::size_t max_entries = bounds_info.found ? bounds_info.bound : config_.max_entries;

                    if (auto table = try_absolute_table(disp, entry_size)) {
                        table->instruction_address = jump_instr.ip();
                        table->entry_count = std::min(table->targets.size(), max_entries);
                        table->targets.resize(table->entry_count);

                        if (bounds_info.found) {
                            table->bounds_check_addr = bounds_info.address;
                            table->max_index = bounds_info.bound;
                            table->confidence = 90;
                        } else {
                            table->confidence = 70;
                        }

                        return table;
                    }
                }

                break;
            }
        }
    }

    return std::nullopt;
}

std::optional<JumpTable> JumpTableAnalyzer::resolve_table(
    Address table_address,
    Address base_address,
    std::size_t entry_size,
    JumpTableEntryType entry_type,
    std::size_t max_entries
) {
    if (max_entries == 0) max_entries = config_.max_entries;

    JumpTable table;
    table.table_address = table_address;
    table.base_address = base_address;
    table.entry_size = entry_size;
    table.entry_type = entry_type;

    switch (entry_type) {
        case JumpTableEntryType::Absolute:
            table.targets = read_absolute_entries(table_address, entry_size, max_entries);
            break;

        case JumpTableEntryType::Relative32:
        case JumpTableEntryType::Relative16:
        case JumpTableEntryType::Relative8:
            table.targets = read_relative_entries(
                table_address, base_address, entry_size, max_entries,
                false  // unsigned
            );
            break;

        case JumpTableEntryType::Index8:
            // Not directly supported here
            return std::nullopt;
    }

    if (table.targets.empty()) return std::nullopt;

    table.entry_count = table.targets.size();
    table.all_targets_valid = validate_targets(table.targets);
    table.confidence = table.all_targets_valid ? 80 : 40;

    return table;
}

std::optional<JumpTable> JumpTableAnalyzer::try_absolute_table(
    Address table_addr,
    std::size_t entry_size
) {
    auto entries = read_absolute_entries(table_addr, entry_size, config_.max_entries);
    if (entries.size() < config_.min_entries) return std::nullopt;

    if (!validate_targets(entries)) return std::nullopt;

    JumpTable table;
    table.table_address = table_addr;
    table.base_address = table_addr;
    table.entry_size = entry_size;
    table.entry_type = JumpTableEntryType::Absolute;
    table.targets = std::move(entries);
    table.entry_count = table.targets.size();
    table.all_targets_valid = true;

    return table;
}

std::optional<JumpTable> JumpTableAnalyzer::try_relative_table(
    Address table_addr,
    Address base_addr,
    std::size_t entry_size,
    bool is_signed
) {
    auto entries = read_relative_entries(
        table_addr, base_addr, entry_size, config_.max_entries, is_signed
    );
    if (entries.size() < config_.min_entries) return std::nullopt;

    if (!validate_targets(entries)) return std::nullopt;

    JumpTable table;
    table.table_address = table_addr;
    table.base_address = base_addr;
    table.entry_size = entry_size;

    switch (entry_size) {
        case 1: table.entry_type = JumpTableEntryType::Relative8; break;
        case 2: table.entry_type = JumpTableEntryType::Relative16; break;
        case 4: table.entry_type = JumpTableEntryType::Relative32; break;
        default: table.entry_type = JumpTableEntryType::Relative32; break;
    }

    table.targets = std::move(entries);
    table.entry_count = table.targets.size();
    table.all_targets_valid = true;

    return table;
}

std::vector<Address> JumpTableAnalyzer::read_absolute_entries(
    Address table_addr,
    std::size_t entry_size,
    std::size_t count
) {
    std::vector<Address> results;
    results.reserve(count);

    auto data = binary_->memory().read(table_addr, count * entry_size);
    if (!data) return results;

    const std::uint8_t* ptr = data->data();
    std::size_t available = data->size() / entry_size;

    for (std::size_t i = 0; i < std::min(count, available); ++i) {
        Address addr = 0;

        switch (entry_size) {
            case 4:
                std::memcpy(&addr, ptr + i * 4, 4);
                break;
            case 8:
                std::memcpy(&addr, ptr + i * 8, 8);
                break;
            default:
                return results;
        }

        // Check if this looks like a valid code address
        if (!binary_->memory().is_executable(addr)) {
            // End of table
            break;
        }

        results.push_back(addr);
    }

    return results;
}

std::vector<Address> JumpTableAnalyzer::read_relative_entries(
    Address table_addr,
    Address base_addr,
    std::size_t entry_size,
    std::size_t count,
    bool is_signed
) {
    std::vector<Address> results;
    results.reserve(count);

    auto data = binary_->memory().read(table_addr, count * entry_size);
    if (!data) return results;

    const std::uint8_t* ptr = data->data();
    std::size_t available = data->size() / entry_size;

    for (std::size_t i = 0; i < std::min(count, available); ++i) {
        std::int64_t offset = 0;

        switch (entry_size) {
            case 1:
                if (is_signed) {
                    offset = static_cast<std::int8_t>(ptr[i]);
                } else {
                    offset = ptr[i];
                }
                break;
            case 2: {
                std::int16_t val;
                std::memcpy(&val, ptr + i * 2, 2);
                offset = is_signed ? val : static_cast<std::uint16_t>(val);
                break;
            }
            case 4: {
                std::int32_t val;
                std::memcpy(&val, ptr + i * 4, 4);
                offset = is_signed ? val : static_cast<std::uint32_t>(val);
                break;
            }
            default:
                return results;
        }

        Address addr = base_addr + offset;

        if (!binary_->memory().is_executable(addr)) {
            break;
        }

        results.push_back(addr);
    }

    return results;
}

bool JumpTableAnalyzer::validate_targets(const std::vector<Address>& targets) const {
    if (targets.empty()) return false;

    for (Address addr : targets) {
        if (!binary_->memory().is_executable(addr)) {
            return false;
        }
    }

    return true;
}

JumpTableAnalyzer::BoundsCheckInfo JumpTableAnalyzer::find_bounds_check(
    const std::vector<Instruction>& instructions,
    std::size_t jump_index
) {
    BoundsCheckInfo info;

    // Look backward for cmp + ja/jae pattern
    // Common pattern: cmp reg, imm; ja default_case; jmp [table + reg * scale]

    for (std::size_t i = jump_index; i > 0 && i > jump_index - 15; --i) {
        const auto& instr = instructions[i - 1];
        const auto& u = instr.raw();

        // Look for conditional jump (ja, jae, jb, jbe for unsigned comparisons)
        if (u.mnemonic() == iced_x86::Mnemonic::JA ||
            u.mnemonic() == iced_x86::Mnemonic::JAE ||
            u.mnemonic() == iced_x86::Mnemonic::JB ||
            u.mnemonic() == iced_x86::Mnemonic::JBE) {

            // Look for preceding cmp
            if (i >= 2) {
                const auto& cmp_instr = instructions[i - 2];
                const auto& cmp = cmp_instr.raw();

                if (cmp.mnemonic() == iced_x86::Mnemonic::CMP &&
                    cmp.op_count() >= 2) {

                    auto op1_kind = cmp.op_kind(1);
                    if (op1_kind == iced_x86::OpKind::IMMEDIATE8 ||
                        op1_kind == iced_x86::OpKind::IMMEDIATE16 ||
                        op1_kind == iced_x86::OpKind::IMMEDIATE32 ||
                        op1_kind == iced_x86::OpKind::IMMEDIATE8TO32 ||
                        op1_kind == iced_x86::OpKind::IMMEDIATE8TO64) {

                        info.found = true;
                        info.address = cmp_instr.ip();
                        info.bound = cmp.immediate64();

                        // Adjust bound based on comparison type
                        if (u.mnemonic() == iced_x86::Mnemonic::JA ||
                            u.mnemonic() == iced_x86::Mnemonic::JAE) {
                            // cmp x, n; ja default means x must be <= n
                            info.bound += 1;
                        }

                        return info;
                    }
                }
            }
        }
    }

    return info;
}

const char* jump_table_entry_type_name(JumpTableEntryType type) {
    switch (type) {
        case JumpTableEntryType::Absolute: return "absolute";
        case JumpTableEntryType::Relative32: return "rel32";
        case JumpTableEntryType::Relative16: return "rel16";
        case JumpTableEntryType::Relative8: return "rel8";
        case JumpTableEntryType::Index8: return "index8";
    }
    return "?";
}

} // namespace picanha::analysis
