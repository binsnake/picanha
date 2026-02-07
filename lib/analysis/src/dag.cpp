#include "picanha/analysis/dag.hpp"
#include <algorithm>
#include <stack>
#include <format>
#include <sstream>

namespace picanha::analysis {

DAGNode::DAGNode(NodeId id, DAGOp op)
    : id_(id)
    , op_(op)
{}

bool DAGNode::is_arithmetic() const noexcept {
    switch (op_) {
        case DAGOp::Add:
        case DAGOp::Sub:
        case DAGOp::Mul:
        case DAGOp::UDiv:
        case DAGOp::SDiv:
        case DAGOp::URem:
        case DAGOp::SRem:
        case DAGOp::Neg:
        case DAGOp::And:
        case DAGOp::Or:
        case DAGOp::Xor:
        case DAGOp::Not:
        case DAGOp::Shl:
        case DAGOp::LShr:
        case DAGOp::AShr:
        case DAGOp::Rol:
        case DAGOp::Ror:
            return true;
        default:
            return false;
    }
}

bool DAGNode::is_comparison() const noexcept {
    switch (op_) {
        case DAGOp::Eq:
        case DAGOp::Ne:
        case DAGOp::ULt:
        case DAGOp::ULe:
        case DAGOp::UGt:
        case DAGOp::UGe:
        case DAGOp::SLt:
        case DAGOp::SLe:
        case DAGOp::SGt:
        case DAGOp::SGe:
            return true;
        default:
            return false;
    }
}

bool DAGNode::is_address_computation() const noexcept {
    switch (op_) {
        case DAGOp::BaseOffset:
        case DAGOp::ScaledIndex:
        case DAGOp::FullAddress:
        case DAGOp::Add:  // Often used for address computation
            return true;
        default:
            return false;
    }
}

NodeId DAG::create_constant(std::uint64_t value, std::uint8_t bit_width) {
    // Check cache
    auto it = constant_cache_.find(value);
    if (it != constant_cache_.end()) {
        return it->second;
    }

    NodeId id = next_id_++;
    auto node = std::make_unique<DAGNode>(id, DAGOp::Constant);
    node->set_value(value);
    node->set_bit_width(bit_width);
    nodes_.push_back(std::move(node));

    constant_cache_[value] = id;
    return id;
}

NodeId DAG::create_register(iced_x86::Register reg) {
    // Check cache
    auto it = register_cache_.find(reg);
    if (it != register_cache_.end()) {
        return it->second;
    }

    NodeId id = next_id_++;
    auto node = std::make_unique<DAGNode>(id, DAGOp::Register);
    node->set_reg(reg);

    // Set bit width based on register size
    auto info = iced_x86::get_register_info(reg);
    node->set_bit_width(static_cast<std::uint8_t>(info.size * 8));

    nodes_.push_back(std::move(node));
    register_cache_[reg] = id;
    return id;
}

NodeId DAG::create_memory(NodeId address_node) {
    NodeId id = next_id_++;
    auto node = std::make_unique<DAGNode>(id, DAGOp::Memory);
    node->add_operand(address_node);
    nodes_.push_back(std::move(node));

    update_users(id);
    return id;
}

NodeId DAG::create_op(DAGOp op, std::vector<NodeId> operands, std::uint8_t bit_width) {
    NodeId id = next_id_++;
    auto node = std::make_unique<DAGNode>(id, op);
    node->set_operands(std::move(operands));
    node->set_bit_width(bit_width);
    nodes_.push_back(std::move(node));

    update_users(id);
    return id;
}

void DAG::update_users(NodeId node_id) {
    auto* node = find_node(node_id);
    if (!node) return;

    for (NodeId operand_id : node->operands()) {
        if (auto* operand = find_node(operand_id)) {
            operand->add_user(node_id);
        }
    }
}

DAGNode& DAG::get_node(NodeId id) {
    return *nodes_.at(id);
}

const DAGNode& DAG::get_node(NodeId id) const {
    return *nodes_.at(id);
}

DAGNode* DAG::find_node(NodeId id) {
    if (id < nodes_.size()) {
        return nodes_[id].get();
    }
    return nullptr;
}

const DAGNode* DAG::find_node(NodeId id) const {
    if (id < nodes_.size()) {
        return nodes_[id].get();
    }
    return nullptr;
}

std::vector<NodeId> DAG::get_roots() const {
    std::vector<NodeId> roots;
    for (const auto& node : nodes_) {
        if (node->users().empty()) {
            roots.push_back(node->id());
        }
    }
    return roots;
}

std::vector<NodeId> DAG::get_leaves() const {
    std::vector<NodeId> leaves;
    for (const auto& node : nodes_) {
        if (node->operands().empty()) {
            leaves.push_back(node->id());
        }
    }
    return leaves;
}

void DAG::for_each_node(NodeVisitor visitor) {
    for (auto& node : nodes_) {
        visitor(*node);
    }
}

void DAG::for_each_node(ConstNodeVisitor visitor) const {
    for (const auto& node : nodes_) {
        visitor(*node);
    }
}

void DAG::traverse_topological(ConstNodeVisitor visitor) const {
    std::vector<bool> visited(nodes_.size(), false);
    std::vector<NodeId> order;
    order.reserve(nodes_.size());

    std::function<void(NodeId)> dfs = [&](NodeId id) {
        if (id >= nodes_.size() || visited[id]) return;
        visited[id] = true;

        for (NodeId operand : nodes_[id]->operands()) {
            dfs(operand);
        }

        order.push_back(id);
    };

    // Start from all roots
    for (const auto& node : nodes_) {
        if (node->users().empty()) {
            dfs(node->id());
        }
    }

    // Visit in order
    for (NodeId id : order) {
        visitor(*nodes_[id]);
    }
}

void DAG::traverse_reverse_topological(ConstNodeVisitor visitor) const {
    std::vector<bool> visited(nodes_.size(), false);
    std::vector<NodeId> order;
    order.reserve(nodes_.size());

    std::function<void(NodeId)> dfs = [&](NodeId id) {
        if (id >= nodes_.size() || visited[id]) return;
        visited[id] = true;

        for (NodeId user : nodes_[id]->users()) {
            dfs(user);
        }

        order.push_back(id);
    };

    // Start from all leaves
    for (const auto& node : nodes_) {
        if (node->operands().empty()) {
            dfs(node->id());
        }
    }

    // Visit in order
    for (NodeId id : order) {
        visitor(*nodes_[id]);
    }
}

std::vector<NodeId> DAG::find_nodes_by_op(DAGOp op) const {
    std::vector<NodeId> result;
    for (const auto& node : nodes_) {
        if (node->op() == op) {
            result.push_back(node->id());
        }
    }
    return result;
}

std::vector<NodeId> DAG::find_address_computations() const {
    std::vector<NodeId> result;
    for (const auto& node : nodes_) {
        if (node->is_address_computation()) {
            result.push_back(node->id());
        }
    }
    return result;
}

std::unique_ptr<DAG> DAG::extract_subgraph(NodeId root) const {
    auto subgraph = std::make_unique<DAG>();

    std::unordered_map<NodeId, NodeId> id_map;
    std::stack<NodeId> worklist;
    worklist.push(root);

    std::unordered_set<NodeId> visited;

    // First pass: collect all nodes
    while (!worklist.empty()) {
        NodeId id = worklist.top();
        worklist.pop();

        if (visited.count(id)) continue;
        visited.insert(id);

        const auto* node = find_node(id);
        if (!node) continue;

        for (NodeId operand : node->operands()) {
            worklist.push(operand);
        }
    }

    // Second pass: create nodes in topological order
    std::vector<NodeId> order(visited.begin(), visited.end());
    std::sort(order.begin(), order.end());

    for (NodeId old_id : order) {
        const auto* old_node = find_node(old_id);
        if (!old_node) continue;

        NodeId new_id;
        if (old_node->op() == DAGOp::Constant) {
            new_id = subgraph->create_constant(old_node->int_value(), old_node->bit_width());
        } else if (old_node->op() == DAGOp::Register) {
            new_id = subgraph->create_register(old_node->reg());
        } else {
            std::vector<NodeId> new_operands;
            for (NodeId operand : old_node->operands()) {
                if (id_map.count(operand)) {
                    new_operands.push_back(id_map[operand]);
                }
            }
            new_id = subgraph->create_op(old_node->op(), std::move(new_operands), old_node->bit_width());
        }

        id_map[old_id] = new_id;
    }

    return subgraph;
}

bool DAG::matches_pattern(NodeId node, const DAG& pattern, NodeId pattern_root) const {
    const auto* n = find_node(node);
    const auto* p = pattern.find_node(pattern_root);

    if (!n || !p) return false;

    // Wildcards in pattern
    if (p->op() == DAGOp::Unknown) {
        return true;
    }

    // Operation must match
    if (n->op() != p->op()) return false;

    // For constants, values must match (unless pattern uses special value)
    if (n->is_constant() && p->is_constant()) {
        if (p->int_value() != 0 && n->int_value() != p->int_value()) {
            return false;
        }
    }

    // Operand count must match
    if (n->operand_count() != p->operand_count()) return false;

    // Recursively match operands
    for (std::size_t i = 0; i < n->operand_count(); ++i) {
        if (!matches_pattern(n->operand(i), pattern, p->operand(i))) {
            return false;
        }
    }

    return true;
}

void DAG::simplify() {
    // Constant folding
    for (auto& node : nodes_) {
        if (node->operand_count() < 2) continue;

        // Check if all operands are constants
        bool all_const = true;
        for (NodeId op : node->operands()) {
            if (const auto* operand = find_node(op)) {
                if (!operand->is_constant()) {
                    all_const = false;
                    break;
                }
            }
        }

        if (!all_const) continue;

        // Fold based on operation
        std::uint64_t result = 0;
        bool can_fold = true;

        const auto* op0 = find_node(node->operand(0));
        const auto* op1 = node->operand_count() > 1 ? find_node(node->operand(1)) : nullptr;

        if (!op0) continue;

        switch (node->op()) {
            case DAGOp::Add:
                if (op1) result = op0->int_value() + op1->int_value();
                break;
            case DAGOp::Sub:
                if (op1) result = op0->int_value() - op1->int_value();
                break;
            case DAGOp::Mul:
                if (op1) result = op0->int_value() * op1->int_value();
                break;
            case DAGOp::And:
                if (op1) result = op0->int_value() & op1->int_value();
                break;
            case DAGOp::Or:
                if (op1) result = op0->int_value() | op1->int_value();
                break;
            case DAGOp::Xor:
                if (op1) result = op0->int_value() ^ op1->int_value();
                break;
            case DAGOp::Shl:
                if (op1) result = op0->int_value() << op1->int_value();
                break;
            case DAGOp::LShr:
                if (op1) result = op0->int_value() >> op1->int_value();
                break;
            default:
                can_fold = false;
                break;
        }

        if (can_fold) {
            node->set_value(result);
        }
    }
}

std::string DAG::to_string() const {
    std::ostringstream ss;
    ss << "DAG with " << nodes_.size() << " nodes:\n";

    for (const auto& node : nodes_) {
        ss << "  " << node_to_string(node->id()) << "\n";
    }

    return ss.str();
}

std::string DAG::node_to_string(NodeId id) const {
    const auto* node = find_node(id);
    if (!node) return "<invalid>";

    std::ostringstream ss;
    ss << "n" << id << " = " << dag_op_name(node->op());

    if (node->is_constant()) {
        ss << " 0x" << std::hex << node->int_value();
    } else if (node->is_register()) {
        ss << " reg" << static_cast<int>(node->reg());
    }

    if (!node->operands().empty()) {
        ss << "(";
        for (std::size_t i = 0; i < node->operands().size(); ++i) {
            if (i > 0) ss << ", ";
            ss << "n" << node->operand(i);
        }
        ss << ")";
    }

    return ss.str();
}

const char* dag_op_name(DAGOp op) {
    switch (op) {
        case DAGOp::Constant: return "const";
        case DAGOp::Register: return "reg";
        case DAGOp::Memory: return "mem";
        case DAGOp::Argument: return "arg";
        case DAGOp::Add: return "add";
        case DAGOp::Sub: return "sub";
        case DAGOp::Mul: return "mul";
        case DAGOp::UDiv: return "udiv";
        case DAGOp::SDiv: return "sdiv";
        case DAGOp::URem: return "urem";
        case DAGOp::SRem: return "srem";
        case DAGOp::Neg: return "neg";
        case DAGOp::And: return "and";
        case DAGOp::Or: return "or";
        case DAGOp::Xor: return "xor";
        case DAGOp::Not: return "not";
        case DAGOp::Shl: return "shl";
        case DAGOp::LShr: return "lshr";
        case DAGOp::AShr: return "ashr";
        case DAGOp::Rol: return "rol";
        case DAGOp::Ror: return "ror";
        case DAGOp::Eq: return "eq";
        case DAGOp::Ne: return "ne";
        case DAGOp::ULt: return "ult";
        case DAGOp::ULe: return "ule";
        case DAGOp::UGt: return "ugt";
        case DAGOp::UGe: return "uge";
        case DAGOp::SLt: return "slt";
        case DAGOp::SLe: return "sle";
        case DAGOp::SGt: return "sgt";
        case DAGOp::SGe: return "sge";
        case DAGOp::ZExt: return "zext";
        case DAGOp::SExt: return "sext";
        case DAGOp::Trunc: return "trunc";
        case DAGOp::Load: return "load";
        case DAGOp::Store: return "store";
        case DAGOp::Branch: return "br";
        case DAGOp::Jump: return "jmp";
        case DAGOp::Call: return "call";
        case DAGOp::Return: return "ret";
        case DAGOp::BaseOffset: return "baseoff";
        case DAGOp::ScaledIndex: return "scaled";
        case DAGOp::FullAddress: return "fulladdr";
        case DAGOp::Phi: return "phi";
        case DAGOp::Select: return "select";
        case DAGOp::Unknown: return "unknown";
    }
    return "?";
}

bool is_commutative(DAGOp op) {
    switch (op) {
        case DAGOp::Add:
        case DAGOp::Mul:
        case DAGOp::And:
        case DAGOp::Or:
        case DAGOp::Xor:
        case DAGOp::Eq:
        case DAGOp::Ne:
            return true;
        default:
            return false;
    }
}

bool is_associative(DAGOp op) {
    switch (op) {
        case DAGOp::Add:
        case DAGOp::Mul:
        case DAGOp::And:
        case DAGOp::Or:
        case DAGOp::Xor:
            return true;
        default:
            return false;
    }
}

} // namespace picanha::analysis
