#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/instruction.hpp>
#include <vector>
#include <span>
#include <string>

namespace picanha::analysis {

// Edge type between basic blocks
enum class EdgeType : std::uint8_t {
    Fallthrough,        // Sequential execution
    UnconditionalJump,  // JMP
    ConditionalTrue,    // Conditional branch taken
    ConditionalFalse,   // Conditional branch not taken (fallthrough)
    Call,               // CALL (edge to callee)
    Return,             // RET (virtual edge back to callers)
    Exception,          // Exception handler edge
    Indirect,           // Indirect jump (unknown target)
};

// Edge to another block
struct BlockEdge {
    BlockId target{INVALID_BLOCK_ID};
    EdgeType type{EdgeType::Fallthrough};
    bool is_back_edge{false};  // Part of a loop

    [[nodiscard]] bool is_valid() const noexcept {
        return target != INVALID_BLOCK_ID;
    }
};

// Basic block - a sequence of instructions with single entry and exit
class BasicBlock {
public:
    BasicBlock() = default;
    BasicBlock(BlockId id, Address start_address);

    // Identity
    [[nodiscard]] BlockId id() const noexcept { return id_; }
    void set_id(BlockId id) noexcept { id_ = id; }

    // Address range
    [[nodiscard]] Address start_address() const noexcept { return start_address_; }
    [[nodiscard]] Address end_address() const noexcept { return end_address_; }
    [[nodiscard]] Size size() const noexcept { return end_address_ - start_address_; }

    void set_start_address(Address addr) noexcept { start_address_ = addr; }
    void set_end_address(Address addr) noexcept { end_address_ = addr; }

    [[nodiscard]] AddressRange address_range() const noexcept {
        return {start_address_, end_address_};
    }

    [[nodiscard]] bool contains(Address addr) const noexcept {
        return addr >= start_address_ && addr < end_address_;
    }

    // Function membership
    [[nodiscard]] FunctionId function_id() const noexcept { return function_id_; }
    void set_function_id(FunctionId id) noexcept { function_id_ = id; }

    // Instructions
    [[nodiscard]] const std::vector<Instruction>& instructions() const noexcept {
        return instructions_;
    }

    [[nodiscard]] std::vector<Instruction>& instructions() noexcept {
        return instructions_;
    }

    void add_instruction(Instruction instr) {
        if (instructions_.empty()) {
            start_address_ = instr.ip();
        }
        end_address_ = instr.next_ip();
        instructions_.push_back(std::move(instr));
    }

    [[nodiscard]] std::size_t instruction_count() const noexcept {
        return instructions_.size();
    }

    [[nodiscard]] const Instruction* first_instruction() const noexcept {
        return instructions_.empty() ? nullptr : &instructions_.front();
    }

    [[nodiscard]] const Instruction* last_instruction() const noexcept {
        return instructions_.empty() ? nullptr : &instructions_.back();
    }

    // Find instruction at address
    [[nodiscard]] const Instruction* instruction_at(Address addr) const;

    // Edges
    [[nodiscard]] const std::vector<BlockEdge>& successors() const noexcept {
        return successors_;
    }

    [[nodiscard]] const std::vector<BlockId>& predecessors() const noexcept {
        return predecessors_;
    }

    void add_successor(BlockEdge edge) {
        successors_.push_back(edge);
    }

    void add_predecessor(BlockId pred) {
        predecessors_.push_back(pred);
    }

    // Block properties
    [[nodiscard]] bool is_entry_block() const noexcept { return is_entry_; }
    [[nodiscard]] bool is_exit_block() const noexcept { return is_exit_; }
    [[nodiscard]] bool is_call_block() const noexcept { return has_call_; }
    [[nodiscard]] bool has_call() const noexcept { return has_call_; }
    [[nodiscard]] bool has_indirect_branch() const noexcept { return has_indirect_; }
    [[nodiscard]] bool has_indirect() const noexcept { return has_indirect_; }

    void set_entry_block(bool v) noexcept { is_entry_ = v; }
    void set_exit_block(bool v) noexcept { is_exit_ = v; }
    void set_has_call(bool v) noexcept { has_call_ = v; }
    void set_has_indirect(bool v) noexcept { has_indirect_ = v; }

    // Terminator type
    [[nodiscard]] FlowType terminator_type() const noexcept {
        if (auto* last = last_instruction()) {
            return last->flow_type();
        }
        return FlowType::Unknown;
    }

    // Loop info
    [[nodiscard]] bool is_loop_header() const noexcept { return is_loop_header_; }
    void set_loop_header(bool v) noexcept { is_loop_header_ = v; }

    // Dominance info (set by analysis)
    [[nodiscard]] BlockId immediate_dominator() const noexcept { return idom_; }
    void set_immediate_dominator(BlockId id) noexcept { idom_ = id; }

private:
    BlockId id_{INVALID_BLOCK_ID};
    FunctionId function_id_{INVALID_FUNCTION_ID};
    Address start_address_{INVALID_ADDRESS};
    Address end_address_{INVALID_ADDRESS};

    std::vector<Instruction> instructions_;
    std::vector<BlockEdge> successors_;
    std::vector<BlockId> predecessors_;

    // Flags
    bool is_entry_{false};
    bool is_exit_{false};
    bool has_call_{false};
    bool has_indirect_{false};
    bool is_loop_header_{false};

    // Dominance
    BlockId idom_{INVALID_BLOCK_ID};
};

// Lightweight block reference (for CFG edges without full block data)
struct BlockRef {
    BlockId id{INVALID_BLOCK_ID};
    Address address{INVALID_ADDRESS};

    [[nodiscard]] bool is_valid() const noexcept {
        return id != INVALID_BLOCK_ID;
    }
};

} // namespace picanha::analysis
