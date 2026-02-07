#include "picanha/analysis/pattern_matcher.hpp"
#include <picanha/disasm/flow_analyzer.hpp>

namespace picanha::analysis {

// DAGBuilder implementation
DAGBuilder::DAGBuilder()
    : dag_(std::make_unique<DAG>())
{}

void DAGBuilder::reset() {
    dag_ = std::make_unique<DAG>();
    register_values_.clear();
}

std::unique_ptr<DAG> DAGBuilder::take_dag() {
    auto result = std::move(dag_);
    reset();
    return result;
}

void DAGBuilder::add_instruction(const Instruction& instr) {
    const auto& underlying = instr.raw();

    // Get instruction info
    auto info = iced_x86::InstructionInfoFactory().info(underlying);

    // Process based on instruction type
    auto mnemonic = underlying.mnemonic();

    switch (mnemonic) {
        case iced_x86::Mnemonic::MOV: {
            // mov dest, src
            if (underlying.op_count() >= 2) {
                NodeId src = process_operand(instr, 1);
                auto dest_kind = underlying.op_kind(0);

                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), src);
                } else if (dest_kind == iced_x86::OpKind::MEMORY) {
                    NodeId addr = process_memory_operand(instr, 0);
                    dag_->create_op(DAGOp::Store, {addr, src});
                }
            }
            break;
        }

        case iced_x86::Mnemonic::LEA: {
            // lea dest, [mem] - just compute address, don't load
            if (underlying.op_count() >= 2) {
                NodeId addr = process_memory_operand(instr, 1);
                auto dest_kind = underlying.op_kind(0);

                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), addr);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::ADD: {
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::Add, {op0, op1});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::SUB: {
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::Sub, {op0, op1});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::IMUL:
        case iced_x86::Mnemonic::MUL: {
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::Mul, {op0, op1});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::AND: {
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::And, {op0, op1});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::OR: {
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::Or, {op0, op1});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::XOR: {
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::Xor, {op0, op1});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::SHL:
        case iced_x86::Mnemonic::SAL: {
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::Shl, {op0, op1});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::SHR: {
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::LShr, {op0, op1});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::SAR: {
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::AShr, {op0, op1});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::CMP: {
            // cmp creates comparison result (affects flags)
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                // Create sub for the comparison (result discarded, flags set)
                dag_->create_op(DAGOp::Sub, {op0, op1});
            }
            break;
        }

        case iced_x86::Mnemonic::TEST: {
            if (underlying.op_count() >= 2) {
                NodeId op0 = process_operand(instr, 0);
                NodeId op1 = process_operand(instr, 1);
                dag_->create_op(DAGOp::And, {op0, op1});
            }
            break;
        }

        case iced_x86::Mnemonic::MOVZX: {
            if (underlying.op_count() >= 2) {
                NodeId src = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::ZExt, {src});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::MOVSX:
        case iced_x86::Mnemonic::MOVSXD: {
            if (underlying.op_count() >= 2) {
                NodeId src = process_operand(instr, 1);
                NodeId result = dag_->create_op(DAGOp::SExt, {src});

                auto dest_kind = underlying.op_kind(0);
                if (dest_kind == iced_x86::OpKind::REGISTER) {
                    define_register(underlying.op_register(0), result);
                }
            }
            break;
        }

        case iced_x86::Mnemonic::JMP: {
            if (underlying.op_count() >= 1) {
                auto kind = underlying.op_kind(0);
                if (kind == iced_x86::OpKind::MEMORY) {
                    NodeId addr = process_memory_operand(instr, 0);
                    NodeId target = dag_->create_op(DAGOp::Load, {addr});
                    dag_->create_op(DAGOp::Jump, {target});
                } else if (kind == iced_x86::OpKind::REGISTER) {
                    NodeId reg = get_register(underlying.op_register(0));
                    dag_->create_op(DAGOp::Jump, {reg});
                }
            }
            break;
        }

        case iced_x86::Mnemonic::CALL: {
            if (underlying.op_count() >= 1) {
                NodeId target = process_operand(instr, 0);
                dag_->create_op(DAGOp::Call, {target});
            }
            break;
        }

        default:
            // Unhandled instruction - create unknown node
            break;
    }
}

void DAGBuilder::add_block(const BasicBlock& block) {
    for (const auto& instr : block.instructions()) {
        add_instruction(instr);
    }
}

void DAGBuilder::add_instructions(const std::vector<Instruction>& instructions) {
    for (const auto& instr : instructions) {
        add_instruction(instr);
    }
}

NodeId DAGBuilder::process_operand(const Instruction& instr, int operand_index) {
    const auto& underlying = instr.raw();
    auto kind = underlying.op_kind(operand_index);

    switch (kind) {
        case iced_x86::OpKind::REGISTER:
            return current_register_value(underlying.op_register(operand_index));

        case iced_x86::OpKind::IMMEDIATE8:
        case iced_x86::OpKind::IMMEDIATE8_2ND:
        case iced_x86::OpKind::IMMEDIATE16:
        case iced_x86::OpKind::IMMEDIATE32:
        case iced_x86::OpKind::IMMEDIATE64:
        case iced_x86::OpKind::IMMEDIATE8TO16:
        case iced_x86::OpKind::IMMEDIATE8TO32:
        case iced_x86::OpKind::IMMEDIATE8TO64:
        case iced_x86::OpKind::IMMEDIATE32TO64:
            return dag_->create_constant(underlying.immediate64());

        case iced_x86::OpKind::MEMORY: {
            NodeId addr = process_memory_operand(instr, operand_index);
            return dag_->create_op(DAGOp::Load, {addr});
        }

        case iced_x86::OpKind::NEAR_BRANCH16:
        case iced_x86::OpKind::NEAR_BRANCH32:
        case iced_x86::OpKind::NEAR_BRANCH64:
            return dag_->create_constant(underlying.near_branch_target());

        case iced_x86::OpKind::FAR_BRANCH16:
        case iced_x86::OpKind::FAR_BRANCH32:
            return dag_->create_constant(underlying.far_branch32());

        default:
            return dag_->create_op(DAGOp::Unknown, {});
    }
}

NodeId DAGBuilder::process_memory_operand(const Instruction& instr, int operand_index) {
    const auto& underlying = instr.raw();

    // Memory operand: [base + index * scale + displacement]
    auto base_reg = underlying.memory_base();
    auto index_reg = underlying.memory_index();
    auto scale = underlying.memory_index_scale();
    auto displacement = underlying.memory_displacement64();

    std::vector<NodeId> addr_parts;

    // Base register
    NodeId base_node = INVALID_NODE_ID;
    if (base_reg != iced_x86::Register::NONE) {
        base_node = current_register_value(base_reg);
    }

    // Index * scale
    NodeId scaled_index = INVALID_NODE_ID;
    if (index_reg != iced_x86::Register::NONE) {
        NodeId index_node = current_register_value(index_reg);

        if (scale > 1) {
            NodeId scale_node = dag_->create_constant(scale);
            scaled_index = dag_->create_op(DAGOp::Mul, {index_node, scale_node});
        } else {
            scaled_index = index_node;
        }
    }

    // Build address computation
    NodeId result = INVALID_NODE_ID;

    if (base_node != INVALID_NODE_ID && scaled_index != INVALID_NODE_ID) {
        // base + index * scale
        result = dag_->create_op(DAGOp::Add, {base_node, scaled_index});
    } else if (base_node != INVALID_NODE_ID) {
        result = base_node;
    } else if (scaled_index != INVALID_NODE_ID) {
        result = scaled_index;
    }

    // Add displacement
    if (displacement != 0) {
        NodeId disp_node = dag_->create_constant(displacement);
        if (result != INVALID_NODE_ID) {
            result = dag_->create_op(DAGOp::Add, {result, disp_node});
        } else {
            result = disp_node;
        }
    }

    // If result is still invalid, create a constant 0
    if (result == INVALID_NODE_ID) {
        result = dag_->create_constant(0);
    }

    return result;
}

NodeId DAGBuilder::get_register(iced_x86::Register reg) {
    return dag_->create_register(reg);
}

void DAGBuilder::define_register(iced_x86::Register reg, NodeId value) {
    register_values_[reg] = value;

    // Also update related registers (e.g., defining RAX also defines EAX, AX, AL)
    // This is a simplification - proper handling would track partial register updates
}

NodeId DAGBuilder::current_register_value(iced_x86::Register reg) {
    auto it = register_values_.find(reg);
    if (it != register_values_.end()) {
        return it->second;
    }
    // No known value, create fresh register node
    return dag_->create_register(reg);
}

// PatternMatcher implementation
PatternMatcher::PatternMatcher(const PatternLibrary& library)
    : library_(library)
{}

std::vector<PatternMatcher::DAGMatchResult> PatternMatcher::find_matches(const DAG& dag) const {
    std::vector<DAGMatchResult> results;

    dag.for_each_node([&](const DAGNode& node) {
        auto matches = library_.match_all(dag, node.id());
        for (auto& [pattern, match] : matches) {
            DAGMatchResult result;
            result.pattern = pattern;
            result.match = std::move(match);
            result.root_node = node.id();
            results.push_back(std::move(result));
        }
    });

    return results;
}

std::vector<PatternMatcher::DAGMatchResult> PatternMatcher::find_matches(
    const BasicBlock& block
) const {
    DAGBuilder builder;
    builder.add_block(block);
    return find_matches(builder.dag());
}

std::optional<PatternMatch> PatternMatcher::match_pattern(
    const DAG& dag,
    NodeId node,
    const std::string& pattern_name
) const {
    const auto* pattern = library_.find(pattern_name);
    if (!pattern) return std::nullopt;

    auto match = pattern->match(dag, node);
    if (match.matched) {
        return match;
    }
    return std::nullopt;
}

std::vector<PatternMatcher::JumpTableCandidate> PatternMatcher::find_jump_table_candidates(
    const DAG& dag
) const {
    std::vector<JumpTableCandidate> results;

    // Look for jump nodes with computed addresses
    auto jumps = dag.find_nodes_by_op(DAGOp::Jump);

    for (NodeId jump_id : jumps) {
        const auto* jump_node = dag.find_node(jump_id);
        if (!jump_node || jump_node->operand_count() < 1) continue;

        NodeId target_node = jump_node->operand(0);
        const auto* target = dag.find_node(target_node);
        if (!target) continue;

        // Check if target is a load (indirect jump through memory)
        if (target->op() != DAGOp::Load) continue;
        if (target->operand_count() < 1) continue;

        NodeId addr_node = target->operand(0);

        // Try to match jump table pattern on the address computation
        if (auto match = match_pattern(dag, addr_node, "base_plus_offset")) {
            JumpTableCandidate candidate;
            candidate.index_node = match->get_node("base");

            // Get base address if it's a constant
            if (auto base_val = match->get_constant("offset", dag)) {
                candidate.base_address = *base_val;
            }

            // Try to find scale in the index computation
            if (auto idx_match = match_pattern(dag, candidate.index_node, "scaled_index")) {
                candidate.index_node = idx_match->get_node("index");
                if (auto scale_val = idx_match->get_constant("scale", dag)) {
                    candidate.scale = *scale_val;
                }
            } else {
                candidate.scale = 8;  // Default for 64-bit pointers
            }

            results.push_back(candidate);
        }
    }

    return results;
}

std::vector<PatternMatcher::BoundsCheckCandidate> PatternMatcher::find_bounds_checks(
    const DAG& dag
) const {
    std::vector<BoundsCheckCandidate> results;

    // Look for comparison nodes
    std::vector<DAGOp> cmp_ops = {
        DAGOp::ULt, DAGOp::ULe, DAGOp::UGt, DAGOp::UGe,
        DAGOp::SLt, DAGOp::SLe, DAGOp::SGt, DAGOp::SGe
    };

    for (auto op : cmp_ops) {
        auto nodes = dag.find_nodes_by_op(op);
        for (NodeId node_id : nodes) {
            const auto* node = dag.find_node(node_id);
            if (!node || node->operand_count() < 2) continue;

            // Check if one operand is a constant (the bound)
            const auto* op0 = dag.find_node(node->operand(0));
            const auto* op1 = dag.find_node(node->operand(1));

            if (!op0 || !op1) continue;

            BoundsCheckCandidate candidate;

            if (op1->is_constant()) {
                candidate.index_node = node->operand(0);
                candidate.bound = op1->int_value();
            } else if (op0->is_constant()) {
                candidate.index_node = node->operand(1);
                candidate.bound = op0->int_value();
            } else {
                continue;  // Neither is constant
            }

            candidate.is_signed = (op == DAGOp::SLt || op == DAGOp::SLe ||
                                   op == DAGOp::SGt || op == DAGOp::SGe);

            results.push_back(candidate);
        }
    }

    return results;
}

// SubgraphMatcher implementation
SubgraphMatcher::MatchResult SubgraphMatcher::match(
    const DAG& pattern,
    const DAG& target,
    NodeId pattern_root,
    NodeId target_root
) {
    MatchResult result;
    std::unordered_set<NodeId> used_target_nodes;

    result.matched = match_recursive(
        pattern, target,
        pattern_root, target_root,
        result.node_mapping,
        used_target_nodes
    );

    return result;
}

std::vector<SubgraphMatcher::MatchResult> SubgraphMatcher::find_all(
    const DAG& pattern,
    const DAG& target
) {
    std::vector<MatchResult> results;

    auto pattern_roots = pattern.get_roots();
    if (pattern_roots.empty()) return results;

    NodeId pattern_root = pattern_roots[0];

    // Try matching at each target node
    target.for_each_node([&](const DAGNode& target_node) {
        auto result = match(pattern, target, pattern_root, target_node.id());
        if (result.matched) {
            results.push_back(std::move(result));
        }
    });

    return results;
}

bool SubgraphMatcher::match_recursive(
    const DAG& pattern,
    const DAG& target,
    NodeId pattern_node,
    NodeId target_node,
    std::unordered_map<NodeId, NodeId>& mapping,
    std::unordered_set<NodeId>& used_target_nodes
) {
    const auto* pn = pattern.find_node(pattern_node);
    const auto* tn = target.find_node(target_node);

    if (!pn || !tn) return false;

    // Check if we already mapped this pattern node
    auto it = mapping.find(pattern_node);
    if (it != mapping.end()) {
        return it->second == target_node;
    }

    // Check if target node is already used
    if (used_target_nodes.count(target_node)) {
        return false;
    }

    // Operations must match (Unknown in pattern is wildcard)
    if (pn->op() != DAGOp::Unknown && pn->op() != tn->op()) {
        return false;
    }

    // For constants, values must match
    if (pn->is_constant() && tn->is_constant()) {
        if (pn->int_value() != 0 && pn->int_value() != tn->int_value()) {
            return false;
        }
    }

    // Operand count must match (for non-wildcards)
    if (pn->op() != DAGOp::Unknown && pn->operand_count() != tn->operand_count()) {
        return false;
    }

    // Tentatively add mapping
    mapping[pattern_node] = target_node;
    used_target_nodes.insert(target_node);

    // Match operands recursively
    for (std::size_t i = 0; i < pn->operand_count(); ++i) {
        if (!match_recursive(pattern, target,
                             pn->operand(i), tn->operand(i),
                             mapping, used_target_nodes)) {
            // Backtrack
            mapping.erase(pattern_node);
            used_target_nodes.erase(target_node);
            return false;
        }
    }

    return true;
}

} // namespace picanha::analysis
