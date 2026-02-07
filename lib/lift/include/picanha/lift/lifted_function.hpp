#pragma once

#include <picanha/core/types.hpp>
#include <picanha/lift/types.hpp>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

// Forward declarations for LLVM types
namespace llvm {
class Function;
class Module;
class Instruction;
} // namespace llvm

namespace picanha::lift {

// A lifted function containing LLVM IR
class LiftedFunction {
public:
    LiftedFunction(FunctionId id, Address entry_address, std::string name);
    ~LiftedFunction();

    // Non-copyable (owns LLVM module)
    LiftedFunction(const LiftedFunction&) = delete;
    LiftedFunction& operator=(const LiftedFunction&) = delete;

    // Movable
    LiftedFunction(LiftedFunction&&) noexcept;
    LiftedFunction& operator=(LiftedFunction&&) noexcept;

    // Identity
    [[nodiscard]] FunctionId id() const noexcept { return id_; }
    [[nodiscard]] Address entry_address() const noexcept { return entry_; }
    [[nodiscard]] const std::string& name() const noexcept { return name_; }

    // IR access
    [[nodiscard]] llvm::Function* function() const noexcept { return function_; }
    [[nodiscard]] llvm::Module* module() const noexcept { return module_.get(); }

    // Set the lifted IR (takes ownership of module)
    void set_module(std::unique_ptr<llvm::Module> module);
    void set_function(llvm::Function* func) noexcept { function_ = func; }

    // IR text representation (generated on demand, cached)
    [[nodiscard]] const std::string& ir_text() const;

    // Optimized IR text for a specific level (empty if not optimized)
    [[nodiscard]] const std::string& optimized_ir_text(OptimizationLevel level) const;

    // Check if optimization is available for a level
    [[nodiscard]] bool has_optimized_ir(OptimizationLevel level) const;

    // Store optimized IR text
    void set_optimized_ir(OptimizationLevel level, std::string ir_text);

    // Address mapping (LLVM instruction -> original binary address)
    void add_address_mapping(const llvm::Instruction* inst, Address addr);
    [[nodiscard]] Address get_original_address(const llvm::Instruction* inst) const;

    // Get all addresses covered by this lifted function
    [[nodiscard]] const std::vector<Address>& covered_addresses() const noexcept {
        return covered_addresses_;
    }
    void add_covered_address(Address addr);

    // Status
    [[nodiscard]] LiftStatus status() const noexcept { return status_; }
    void set_status(LiftStatus s) noexcept;

    // Error handling
    [[nodiscard]] const std::string& error_message() const noexcept { return error_; }
    void set_error(std::string msg);

    // Invalidate cached IR text (call after modifications)
    void invalidate_ir_cache() noexcept { ir_text_dirty_ = true; }

private:
    void regenerate_ir_text() const;

    FunctionId id_;
    Address entry_;
    std::string name_;

    std::unique_ptr<llvm::Module> module_;
    llvm::Function* function_{nullptr};

    // Cached IR text
    mutable std::string ir_text_;
    mutable bool ir_text_dirty_{true};

    // Optimized IR for different levels
    mutable std::unordered_map<OptimizationLevel, std::string> optimized_ir_;

    // Address mappings
    std::unordered_map<const llvm::Instruction*, Address> address_map_;
    std::vector<Address> covered_addresses_;

    LiftStatus status_{LiftStatus::Pending};
    std::string error_;
};

} // namespace picanha::lift
