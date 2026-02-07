#include "picanha/analysis/pattern.hpp"
#include <cmath>

namespace picanha::analysis {

std::optional<std::uint64_t> PatternMatch::get_constant(
    const std::string& name,
    const DAG& dag
) const {
    auto it = captures.find(name);
    if (it == captures.end()) return std::nullopt;

    const auto* node = dag.find_node(it->second);
    if (!node || !node->is_constant()) return std::nullopt;

    return node->int_value();
}

std::optional<iced_x86::Register> PatternMatch::get_register(
    const std::string& name,
    const DAG& dag
) const {
    auto it = captures.find(name);
    if (it == captures.end()) return std::nullopt;

    const auto* node = dag.find_node(it->second);
    if (!node || !node->is_register()) return std::nullopt;

    return node->reg();
}

NodeId PatternMatch::get_node(const std::string& name) const {
    auto it = captures.find(name);
    return it != captures.end() ? it->second : INVALID_NODE_ID;
}

Pattern::Pattern(std::string name)
    : name_(std::move(name))
{}

std::size_t Pattern::add_node(PatternNode node) {
    std::size_t index = nodes_.size();
    nodes_.push_back(std::move(node));
    return index;
}

const PatternNode& Pattern::get_node(std::size_t index) const {
    return nodes_.at(index);
}

PatternMatch Pattern::match(const DAG& dag, NodeId node) const {
    PatternMatch result;
    result.matched = match_node(dag, node, root_, result);
    return result;
}

bool Pattern::match_node(
    const DAG& dag,
    NodeId dag_node,
    std::size_t pattern_index,
    PatternMatch& result
) const {
    const auto* dn = dag.find_node(dag_node);
    if (!dn) return false;

    const auto& pn = nodes_[pattern_index];

    // Wildcard matches anything
    if (pn.is_wildcard) {
        if (pn.has_capture()) {
            result.captures[pn.name] = dag_node;
        }
        return check_constraints(dag, dag_node, pn);
    }

    // Constant wildcard
    if (pn.is_constant_wildcard) {
        if (!dn->is_constant()) return false;
        if (pn.has_capture()) {
            result.captures[pn.name] = dag_node;
        }
        return check_constraints(dag, dag_node, pn);
    }

    // Register wildcard
    if (pn.is_register_wildcard) {
        if (!dn->is_register()) return false;
        if (pn.has_capture()) {
            result.captures[pn.name] = dag_node;
        }
        return check_constraints(dag, dag_node, pn);
    }

    // Operation must match (if not Unknown)
    if (pn.op != DAGOp::Unknown && dn->op() != pn.op) {
        return false;
    }

    // Check constraints
    if (!check_constraints(dag, dag_node, pn)) {
        return false;
    }

    // Child count must match
    if (pn.children.size() != dn->operand_count()) {
        return false;
    }

    // Match children recursively
    for (std::size_t i = 0; i < pn.children.size(); ++i) {
        if (!match_node(dag, dn->operand(i), pn.children[i], result)) {
            return false;
        }
    }

    // Capture if named
    if (pn.has_capture()) {
        result.captures[pn.name] = dag_node;
    }

    return true;
}

bool Pattern::check_constraints(
    const DAG& dag,
    NodeId dag_node,
    const PatternNode& pattern_node
) const {
    const auto* node = dag.find_node(dag_node);
    if (!node) return false;

    for (const auto& constraint : pattern_node.constraints) {
        switch (constraint.type) {
            case PatternConstraint::None:
                break;

            case PatternConstraint::IsConstant:
                if (!node->is_constant()) return false;
                break;

            case PatternConstraint::IsRegister:
                if (!node->is_register()) return false;
                break;

            case PatternConstraint::IsMemory:
                if (!node->is_memory()) return false;
                break;

            case PatternConstraint::IsPowerOf2:
                if (!node->is_constant()) return false;
                {
                    auto val = node->int_value();
                    if (val == 0 || (val & (val - 1)) != 0) return false;
                }
                break;

            case PatternConstraint::IsInRange:
                if (!node->is_constant()) return false;
                {
                    auto val = node->int_value();
                    if (val < constraint.value1 || val > constraint.value2) return false;
                }
                break;

            case PatternConstraint::HasBitWidth:
                if (node->bit_width() != static_cast<std::uint8_t>(constraint.value1)) {
                    return false;
                }
                break;

            case PatternConstraint::MatchesRegClass:
                // TODO: Implement register class matching
                break;
        }
    }

    return true;
}

// Static pattern builders
Pattern Pattern::jump_table_load() {
    Pattern p("jump_table_load");

    // Pattern: load(add(base, mul(index, scale)))
    // or: load(add(base, shl(index, log2_scale)))

    // Wildcard for index
    PatternNode index_node;
    index_node.name = "index";
    index_node.is_wildcard = true;
    auto idx = p.add_node(index_node);

    // Scale constant (power of 2: 1, 2, 4, 8)
    PatternNode scale_node;
    scale_node.name = "scale";
    scale_node.is_constant_wildcard = true;
    scale_node.constraints.push_back({PatternConstraint::IsPowerOf2});
    scale_node.constraints.push_back({PatternConstraint::IsInRange, 1, 8});
    auto scale = p.add_node(scale_node);

    // Multiply or shift
    PatternNode mul_node;
    mul_node.name = "scaled_index";
    mul_node.op = DAGOp::Mul;
    mul_node.children = {idx, scale};
    auto mul = p.add_node(mul_node);

    // Base address
    PatternNode base_node;
    base_node.name = "base";
    base_node.is_wildcard = true;
    auto base = p.add_node(base_node);

    // Add base + scaled_index
    PatternNode add_node;
    add_node.name = "address";
    add_node.op = DAGOp::Add;
    add_node.children = {base, mul};
    auto add = p.add_node(add_node);

    // Load from computed address
    PatternNode load_node;
    load_node.name = "load";
    load_node.op = DAGOp::Load;
    load_node.children = {add};
    auto load = p.add_node(load_node);

    p.set_root(load);
    return p;
}

Pattern Pattern::scaled_index() {
    Pattern p("scaled_index");

    // Pattern: mul(index, scale) or shl(index, log2_scale)

    PatternNode index_node;
    index_node.name = "index";
    index_node.is_wildcard = true;
    auto idx = p.add_node(index_node);

    PatternNode scale_node;
    scale_node.name = "scale";
    scale_node.is_constant_wildcard = true;
    scale_node.constraints.push_back({PatternConstraint::IsPowerOf2});
    auto scale = p.add_node(scale_node);

    PatternNode mul_node;
    mul_node.name = "result";
    mul_node.op = DAGOp::Mul;
    mul_node.children = {idx, scale};
    auto mul = p.add_node(mul_node);

    p.set_root(mul);
    return p;
}

Pattern Pattern::base_plus_offset() {
    Pattern p("base_plus_offset");

    PatternNode base_node;
    base_node.name = "base";
    base_node.is_wildcard = true;
    auto base = p.add_node(base_node);

    PatternNode offset_node;
    offset_node.name = "offset";
    offset_node.is_constant_wildcard = true;
    auto offset = p.add_node(offset_node);

    PatternNode add_node;
    add_node.name = "result";
    add_node.op = DAGOp::Add;
    add_node.children = {base, offset};
    auto add = p.add_node(add_node);

    p.set_root(add);
    return p;
}

Pattern Pattern::compare_and_branch() {
    Pattern p("compare_and_branch");

    // Pattern for: cmp(value, bound)

    PatternNode value_node;
    value_node.name = "value";
    value_node.is_wildcard = true;
    auto value = p.add_node(value_node);

    PatternNode bound_node;
    bound_node.name = "bound";
    bound_node.is_constant_wildcard = true;
    auto bound = p.add_node(bound_node);

    // Could be ULt, ULe, UGt, UGe for unsigned, or signed variants
    PatternNode cmp_node;
    cmp_node.name = "comparison";
    cmp_node.op = DAGOp::Unknown;  // Match any comparison
    cmp_node.children = {value, bound};
    auto cmp = p.add_node(cmp_node);

    p.set_root(cmp);
    return p;
}

Pattern Pattern::bounds_check() {
    Pattern p("bounds_check");

    // Pattern: uge(index, bound) or ult(index, bound)
    // Common in switch statements: if (index >= case_count) goto default

    PatternNode index_node;
    index_node.name = "index";
    index_node.is_wildcard = true;
    auto idx = p.add_node(index_node);

    PatternNode bound_node;
    bound_node.name = "bound";
    bound_node.is_constant_wildcard = true;
    auto bound = p.add_node(bound_node);

    PatternNode cmp_node;
    cmp_node.name = "check";
    cmp_node.op = DAGOp::UGe;
    cmp_node.children = {idx, bound};
    auto cmp = p.add_node(cmp_node);

    p.set_root(cmp);
    return p;
}

// PatternLibrary implementation
PatternLibrary::PatternLibrary() = default;

void PatternLibrary::add(Pattern pattern) {
    name_to_index_[pattern.name()] = patterns_.size();
    patterns_.push_back(std::move(pattern));
}

const Pattern* PatternLibrary::find(const std::string& name) const {
    auto it = name_to_index_.find(name);
    if (it != name_to_index_.end()) {
        return &patterns_[it->second];
    }
    return nullptr;
}

std::vector<std::pair<const Pattern*, PatternMatch>>
PatternLibrary::match_all(const DAG& dag, NodeId node) const {
    std::vector<std::pair<const Pattern*, PatternMatch>> results;

    for (const auto& pattern : patterns_) {
        auto match = pattern.match(dag, node);
        if (match.matched) {
            results.emplace_back(&pattern, std::move(match));
        }
    }

    return results;
}

// Builtin patterns singleton
const PatternLibrary& builtin_patterns() {
    static PatternLibrary library = []() {
        PatternLibrary lib;
        lib.add(Pattern::jump_table_load());
        lib.add(Pattern::scaled_index());
        lib.add(Pattern::base_plus_offset());
        lib.add(Pattern::compare_and_branch());
        lib.add(Pattern::bounds_check());
        return lib;
    }();

    return library;
}

} // namespace picanha::analysis
