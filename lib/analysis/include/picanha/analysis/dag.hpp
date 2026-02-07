#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/instruction.hpp>
#include <cstdint>
#include <vector>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <functional>
#include <variant>

namespace picanha::analysis {

// Forward declarations
class DAGNode;
class DAG;

// Unique identifier for DAG nodes
using NodeId = std::uint32_t;
constexpr NodeId INVALID_NODE_ID = static_cast<NodeId>(-1);

// Node operation type - represents the semantic operation
enum class DAGOp : std::uint16_t {
    // Constants and inputs
    Constant,           // Immediate value
    Register,           // Register read
    Memory,             // Memory read
    Argument,           // Function argument

    // Arithmetic
    Add,
    Sub,
    Mul,
    UDiv,               // Unsigned division
    SDiv,               // Signed division
    URem,               // Unsigned remainder
    SRem,               // Signed remainder
    Neg,                // Negation

    // Bitwise
    And,
    Or,
    Xor,
    Not,
    Shl,                // Shift left
    LShr,               // Logical shift right
    AShr,               // Arithmetic shift right
    Rol,                // Rotate left
    Ror,                // Rotate right

    // Comparisons (produce 1 or 0)
    Eq,
    Ne,
    ULt,                // Unsigned less than
    ULe,                // Unsigned less or equal
    UGt,                // Unsigned greater than
    UGe,                // Unsigned greater or equal
    SLt,                // Signed less than
    SLe,                // Signed less or equal
    SGt,                // Signed greater than
    SGe,                // Signed greater or equal

    // Extensions
    ZExt,               // Zero extend
    SExt,               // Sign extend
    Trunc,              // Truncate

    // Memory operations
    Load,               // Memory load
    Store,              // Memory store (side effect)

    // Control flow (for tracking)
    Branch,             // Conditional branch
    Jump,               // Unconditional jump
    Call,               // Function call
    Return,             // Return

    // Address computation
    BaseOffset,         // base + offset
    ScaledIndex,        // base + index * scale
    FullAddress,        // base + index * scale + offset

    // Special
    Phi,                // SSA phi node
    Select,             // Conditional select (like ternary)
    Unknown,            // Unknown operation
};

// Value types for constants
// Note: Address is std::uint64_t, so we just use one integral type
using ConstantValue = std::variant<
    std::uint64_t,      // Integer / Address constant
    double              // Float (for future use)
>;

// DAG Node - represents a single operation in the expression tree
class DAGNode {
public:
    DAGNode(NodeId id, DAGOp op);

    // Identity
    [[nodiscard]] NodeId id() const noexcept { return id_; }
    [[nodiscard]] DAGOp op() const noexcept { return op_; }

    // Operands (children in the DAG)
    [[nodiscard]] const std::vector<NodeId>& operands() const noexcept { return operands_; }
    [[nodiscard]] std::size_t operand_count() const noexcept { return operands_.size(); }
    [[nodiscard]] NodeId operand(std::size_t idx) const { return operands_.at(idx); }

    void add_operand(NodeId id) { operands_.push_back(id); }
    void set_operands(std::vector<NodeId> ops) { operands_ = std::move(ops); }

    // Value (for constants)
    [[nodiscard]] bool has_value() const noexcept { return has_value_; }
    [[nodiscard]] const ConstantValue& value() const { return value_; }
    [[nodiscard]] std::uint64_t int_value() const { return std::get<std::uint64_t>(value_); }

    void set_value(ConstantValue val) {
        value_ = std::move(val);
        has_value_ = true;
    }

    // Register (for Register nodes)
    [[nodiscard]] iced_x86::Register reg() const noexcept { return reg_; }
    void set_reg(iced_x86::Register r) noexcept { reg_ = r; }

    // Bit width
    [[nodiscard]] std::uint8_t bit_width() const noexcept { return bit_width_; }
    void set_bit_width(std::uint8_t w) noexcept { bit_width_ = w; }

    // Source instruction (if tracking provenance)
    [[nodiscard]] Address source_address() const noexcept { return source_addr_; }
    void set_source_address(Address addr) noexcept { source_addr_ = addr; }

    // Users (nodes that use this node as operand)
    [[nodiscard]] const std::vector<NodeId>& users() const noexcept { return users_; }
    void add_user(NodeId id) { users_.push_back(id); }

    // Flags
    [[nodiscard]] bool is_constant() const noexcept { return op_ == DAGOp::Constant; }
    [[nodiscard]] bool is_register() const noexcept { return op_ == DAGOp::Register; }
    [[nodiscard]] bool is_memory() const noexcept { return op_ == DAGOp::Memory || op_ == DAGOp::Load; }
    [[nodiscard]] bool is_arithmetic() const noexcept;
    [[nodiscard]] bool is_comparison() const noexcept;
    [[nodiscard]] bool is_address_computation() const noexcept;

private:
    NodeId id_;
    DAGOp op_;
    std::vector<NodeId> operands_;
    std::vector<NodeId> users_;

    ConstantValue value_;
    bool has_value_{false};

    iced_x86::Register reg_{iced_x86::Register::NONE};
    std::uint8_t bit_width_{64};
    Address source_addr_{INVALID_ADDRESS};
};

// DAG - Directed Acyclic Graph for expression analysis
class DAG {
public:
    DAG() = default;

    // Node creation
    NodeId create_constant(std::uint64_t value, std::uint8_t bit_width = 64);
    NodeId create_register(iced_x86::Register reg);
    NodeId create_memory(NodeId address_node);
    NodeId create_op(DAGOp op, std::vector<NodeId> operands, std::uint8_t bit_width = 64);

    // Node access
    [[nodiscard]] DAGNode& get_node(NodeId id);
    [[nodiscard]] const DAGNode& get_node(NodeId id) const;
    [[nodiscard]] DAGNode* find_node(NodeId id);
    [[nodiscard]] const DAGNode* find_node(NodeId id) const;

    // Node count
    [[nodiscard]] std::size_t node_count() const noexcept { return nodes_.size(); }
    [[nodiscard]] bool is_empty() const noexcept { return nodes_.empty(); }

    // Root nodes (nodes with no users - typically the "result" nodes)
    [[nodiscard]] std::vector<NodeId> get_roots() const;

    // Leaf nodes (nodes with no operands - constants, registers)
    [[nodiscard]] std::vector<NodeId> get_leaves() const;

    // Iteration
    using NodeVisitor = std::function<void(DAGNode&)>;
    using ConstNodeVisitor = std::function<void(const DAGNode&)>;

    void for_each_node(NodeVisitor visitor);
    void for_each_node(ConstNodeVisitor visitor) const;

    // Topological traversal (operands before users)
    void traverse_topological(ConstNodeVisitor visitor) const;

    // Reverse topological (users before operands)
    void traverse_reverse_topological(ConstNodeVisitor visitor) const;

    // Find nodes matching criteria
    [[nodiscard]] std::vector<NodeId> find_nodes_by_op(DAGOp op) const;
    [[nodiscard]] std::vector<NodeId> find_address_computations() const;

    // Subgraph extraction
    [[nodiscard]] std::unique_ptr<DAG> extract_subgraph(NodeId root) const;

    // Pattern matching support
    [[nodiscard]] bool matches_pattern(NodeId node, const DAG& pattern, NodeId pattern_root) const;

    // Simplification
    void simplify();

    // Debug
    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] std::string node_to_string(NodeId id) const;

private:
    void update_users(NodeId node_id);

    std::vector<std::unique_ptr<DAGNode>> nodes_;
    NodeId next_id_{0};

    // Cache for common nodes
    std::unordered_map<std::uint64_t, NodeId> constant_cache_;
    std::unordered_map<iced_x86::Register, NodeId> register_cache_;
};

// Helper to get operation name
[[nodiscard]] const char* dag_op_name(DAGOp op);

// Helper to check if operation is commutative
[[nodiscard]] bool is_commutative(DAGOp op);

// Helper to check if operation is associative
[[nodiscard]] bool is_associative(DAGOp op);

} // namespace picanha::analysis
