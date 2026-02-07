#include "picanha/analysis/switch_analyzer.hpp"
#include <algorithm>
#include <unordered_set>

namespace picanha::analysis {

const SwitchCase* SwitchStatement::find_case(std::int64_t value) const {
    for (const auto& c : cases) {
        if (c.is_range) {
            if (value >= c.value && value <= c.range_end) {
                return &c;
            }
        } else if (c.value == value) {
            return &c;
        }
    }
    return nullptr;
}

const SwitchCase* SwitchStatement::find_case_by_target(Address target) const {
    for (const auto& c : cases) {
        if (c.target == target) {
            return &c;
        }
    }
    if (default_case && default_case->target == target) {
        return &default_case.value();
    }
    return nullptr;
}

SwitchAnalyzer::SwitchAnalyzer(
    std::shared_ptr<loader::Binary> binary,
    const SwitchAnalyzerConfig& config
)
    : binary_(binary)
    , config_(config)
    , jt_analyzer_(binary)
{}

std::vector<SwitchStatement> SwitchAnalyzer::analyze_function(
    const Function& function
) {
    return analyze_cfg(function.cfg());
}

std::vector<SwitchStatement> SwitchAnalyzer::analyze_cfg(const CFG& cfg) {
    std::vector<SwitchStatement> results;

    // First, find jump tables
    auto jump_tables = jt_analyzer_.analyze_function(cfg);

    for (const auto& table : jump_tables) {
        auto sw = from_jump_table(table, cfg);
        if (sw.case_count() > 0) {
            results.push_back(std::move(sw));
        }
    }

    // Optionally detect if-else chains
    if (config_.detect_cascaded_ifs) {
        // Find blocks with multiple comparisons to constants
        cfg.for_each_block([&](const BasicBlock& block) {
            // Skip blocks already part of a switch
            bool already_handled = false;
            for (const auto& sw : results) {
                if (sw.find_case_by_target(block.start_address())) {
                    already_handled = true;
                    break;
                }
            }

            if (!already_handled) {
                if (auto sw = detect_if_chain(cfg, block.id())) {
                    if (sw->case_count() >= 3) {  // At least 3 cases to be a switch
                        results.push_back(std::move(*sw));
                    }
                }
            }
        });
    }

    return results;
}

SwitchStatement SwitchAnalyzer::from_jump_table(
    const JumpTable& table,
    const CFG& cfg
) {
    SwitchStatement sw;
    sw.address = table.instruction_address;
    sw.jump_table = &table;
    sw.confidence = table.confidence;

    // Create cases from jump table entries
    for (std::size_t i = 0; i < table.targets.size(); ++i) {
        SwitchCase c;
        c.value = static_cast<std::int64_t>(i);
        c.target = table.targets[i];

        // Find target block
        if (const auto* block = cfg.find_block_starting_at(c.target)) {
            c.target_block = block->id();
        }

        sw.cases.push_back(c);
    }

    if (!sw.cases.empty()) {
        sw.min_value = sw.cases.front().value;
        sw.max_value = sw.cases.back().value;
    }

    // Try to find default case
    if (auto def = find_default_case(cfg, table.instruction_address, table)) {
        sw.default_case = std::move(def);
    }

    // Merge cases with same target if configured
    if (config_.merge_adjacent_cases) {
        merge_cases(sw);
    }

    sw.is_complete = true;
    return sw;
}

std::optional<SwitchStatement> SwitchAnalyzer::detect_if_chain(
    const CFG& cfg,
    BlockId start_block
) {
    const auto* block = cfg.find_block(start_block);
    if (!block) return std::nullopt;

    SwitchStatement sw;
    sw.address = block->start_address();

    std::unordered_set<BlockId> visited;
    std::vector<const BasicBlock*> chain;

    // Follow the comparison chain
    const BasicBlock* current = block;
    while (current && !visited.count(current->id())) {
        visited.insert(current->id());

        auto cmp_info = analyze_comparison_block(*current);
        if (!cmp_info.found) break;

        chain.push_back(current);

        SwitchCase c;
        c.value = cmp_info.value;
        c.target = cmp_info.true_target;

        if (const auto* target_block = cfg.find_block_starting_at(c.target)) {
            c.target_block = target_block->id();
        }

        sw.cases.push_back(c);

        // Follow false branch for next comparison
        const auto* false_block = cfg.find_block_starting_at(cmp_info.false_target);
        current = false_block;

        // Limit chain length
        if (chain.size() > config_.max_cases) break;
    }

    // If we stopped at a block with no comparison, it might be the default
    if (current && !analyze_comparison_block(*current).found) {
        SwitchCase def;
        def.is_default = true;
        def.target = current->start_address();
        def.target_block = current->id();
        sw.default_case = def;
    }

    if (sw.cases.size() < 2) {
        return std::nullopt;
    }

    // Sort cases by value
    std::sort(sw.cases.begin(), sw.cases.end(),
        [](const SwitchCase& a, const SwitchCase& b) {
            return a.value < b.value;
        });

    sw.min_value = sw.cases.front().value;
    sw.max_value = sw.cases.back().value;
    sw.confidence = 60;  // Lower confidence for if-chain detection

    return sw;
}

std::optional<SwitchCase> SwitchAnalyzer::find_default_case(
    const CFG& cfg,
    Address jump_address,
    const JumpTable& table
) {
    // Look for the bounds check that jumps to default on failure
    // Pattern: cmp reg, max_cases; ja default

    // Find block containing the jump
    const auto* jump_block = cfg.find_block_at(jump_address);
    if (!jump_block) return std::nullopt;

    // Look at predecessors for bounds check
    for (BlockId pred_id : jump_block->predecessors()) {
        const auto* pred = cfg.find_block(pred_id);
        if (!pred) continue;

        // Check if predecessor has conditional branch
        const auto* last = pred->last_instruction();
        if (!last) continue;

        const auto& u = last->raw();
        auto mnemonic = u.mnemonic();

        // ja (jump if above) to default case
        if (mnemonic == iced_x86::Mnemonic::JA ||
            mnemonic == iced_x86::Mnemonic::JAE) {

            if (u.op_count() >= 1) {
                auto op_kind = u.op_kind(0);
                if (op_kind == iced_x86::OpKind::NEAR_BRANCH64 ||
                    op_kind == iced_x86::OpKind::NEAR_BRANCH32) {

                    Address default_target = u.near_branch_target();

                    SwitchCase def;
                    def.is_default = true;
                    def.target = default_target;

                    if (const auto* block = cfg.find_block_starting_at(default_target)) {
                        def.target_block = block->id();
                    }

                    return def;
                }
            }
        }
    }

    return std::nullopt;
}

void SwitchAnalyzer::merge_cases(SwitchStatement& sw) {
    if (sw.cases.size() < 2) return;

    std::vector<SwitchCase> merged;
    merged.reserve(sw.cases.size());

    // Sort by value first
    std::sort(sw.cases.begin(), sw.cases.end(),
        [](const SwitchCase& a, const SwitchCase& b) {
            return a.value < b.value;
        });

    SwitchCase current = sw.cases[0];

    for (std::size_t i = 1; i < sw.cases.size(); ++i) {
        const auto& next = sw.cases[i];

        // If same target and consecutive values, merge into range
        if (next.target == current.target && next.value == current.value + 1) {
            if (!current.is_range) {
                current.is_range = true;
                current.range_end = next.value;
            } else {
                current.range_end = next.value;
            }
        } else if (next.target == current.target &&
                   (next.value - (current.is_range ? current.range_end : current.value)) <=
                   config_.max_value_gap) {
            // Same target but with gap - still merge if gap is small
            if (!current.is_range) {
                current.is_range = true;
                current.range_end = next.value;
            } else {
                current.range_end = next.value;
            }
        } else {
            merged.push_back(current);
            current = next;
        }
    }

    merged.push_back(current);
    sw.cases = std::move(merged);
}

SwitchAnalyzer::ComparisonInfo SwitchAnalyzer::analyze_comparison_block(
    const BasicBlock& block
) {
    ComparisonInfo info;

    // Look for pattern: cmp reg, imm; je/jne target
    const auto& instructions = block.instructions();
    if (instructions.size() < 2) return info;

    // Find cmp instruction
    const Instruction* cmp_instr = nullptr;
    const Instruction* jcc_instr = nullptr;

    for (auto it = instructions.rbegin(); it != instructions.rend(); ++it) {
        const auto& u = it->raw();

        // First find conditional jump
        if (!jcc_instr) {
            auto mnemonic = u.mnemonic();
            if (mnemonic == iced_x86::Mnemonic::JE ||
                mnemonic == iced_x86::Mnemonic::JNE ||
                mnemonic == iced_x86::Mnemonic::JE ||
                mnemonic == iced_x86::Mnemonic::JNE) {
                jcc_instr = &(*it);
            }
        }
        // Then find cmp
        else if (!cmp_instr) {
            if (u.mnemonic() == iced_x86::Mnemonic::CMP) {
                cmp_instr = &(*it);
                break;
            }
        }
    }

    if (!cmp_instr || !jcc_instr) return info;

    const auto& cmp_u = cmp_instr->raw();
    const auto& jcc_u = jcc_instr->raw();

    // Get comparison value
    if (cmp_u.op_count() >= 2) {
        auto op_kind = cmp_u.op_kind(1);
        if (op_kind == iced_x86::OpKind::IMMEDIATE8 ||
            op_kind == iced_x86::OpKind::IMMEDIATE32 ||
            op_kind == iced_x86::OpKind::IMMEDIATE8TO32 ||
            op_kind == iced_x86::OpKind::IMMEDIATE8TO64) {
            info.value = static_cast<std::int64_t>(cmp_u.immediate64());
        } else {
            return info;
        }
    }

    // Get branch targets
    if (jcc_u.op_count() >= 1) {
        info.true_target = jcc_u.near_branch_target();

        // False target is next instruction (fallthrough)
        info.false_target = jcc_instr->next_ip();

        // Swap if jne (jump if not equal means value doesn't match)
        if (jcc_u.mnemonic() == iced_x86::Mnemonic::JNE ||
            jcc_u.mnemonic() == iced_x86::Mnemonic::JNE) {
            std::swap(info.true_target, info.false_target);
        }

        info.found = true;
    }

    return info;
}

SwitchStyle classify_switch(const SwitchStatement& sw) {
    if (sw.jump_table) {
        auto type = sw.jump_table->entry_type;
        if (type == JumpTableEntryType::Absolute) {
            return SwitchStyle::JumpTable;
        } else {
            return SwitchStyle::RelativeJumpTable;
        }
    }

    // Check if all case values form a continuous sequence
    bool is_continuous = true;
    for (std::size_t i = 1; i < sw.cases.size(); ++i) {
        if (sw.cases[i].value != sw.cases[i-1].value + 1) {
            is_continuous = false;
            break;
        }
    }

    if (!is_continuous) {
        return SwitchStyle::IfElseChain;
    }

    return SwitchStyle::Unknown;
}

const char* switch_style_name(SwitchStyle style) {
    switch (style) {
        case SwitchStyle::JumpTable: return "jump_table";
        case SwitchStyle::RelativeJumpTable: return "relative_jump_table";
        case SwitchStyle::IfElseChain: return "if_else_chain";
        case SwitchStyle::BinarySearch: return "binary_search";
        case SwitchStyle::Mixed: return "mixed";
        case SwitchStyle::Unknown: return "unknown";
    }
    return "?";
}

} // namespace picanha::analysis
