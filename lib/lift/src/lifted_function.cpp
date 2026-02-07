#include <picanha/lift/lifted_function.hpp>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>

namespace picanha::lift {

LiftedFunction::LiftedFunction(FunctionId id, Address entry_address, std::string name)
    : id_(id)
    , entry_(entry_address)
    , name_(std::move(name))
{
}

LiftedFunction::~LiftedFunction() = default;

LiftedFunction::LiftedFunction(LiftedFunction&&) noexcept = default;
LiftedFunction& LiftedFunction::operator=(LiftedFunction&&) noexcept = default;

void LiftedFunction::set_module(std::unique_ptr<llvm::Module> module) {
    module_ = std::move(module);
    ir_text_dirty_ = true;
}

const std::string& LiftedFunction::ir_text() const {
    if (ir_text_dirty_ && module_) {
        regenerate_ir_text();
    }
    return ir_text_;
}

void LiftedFunction::regenerate_ir_text() const {
    ir_text_.clear();

    if (!module_) {
        ir_text_ = "; No module available\n";
        ir_text_dirty_ = false;
        return;
    }

    llvm::raw_string_ostream os(ir_text_);

    if (function_) {
        // Print just the function
        function_->print(os);
    } else {
        // Print the entire module
        module_->print(os, nullptr);
    }

    ir_text_dirty_ = false;
}

const std::string& LiftedFunction::optimized_ir_text(OptimizationLevel level) const {
    static const std::string empty;
    auto it = optimized_ir_.find(level);
    if (it == optimized_ir_.end()) {
        return empty;
    }
    return it->second;
}

bool LiftedFunction::has_optimized_ir(OptimizationLevel level) const {
    return optimized_ir_.find(level) != optimized_ir_.end();
}

void LiftedFunction::set_optimized_ir(OptimizationLevel level, std::string ir_text) {
    optimized_ir_[level] = std::move(ir_text);
}

void LiftedFunction::add_address_mapping(const llvm::Instruction* inst, Address addr) {
    if (inst) {
        address_map_[inst] = addr;
    }
}

Address LiftedFunction::get_original_address(const llvm::Instruction* inst) const {
    auto it = address_map_.find(inst);
    if (it == address_map_.end()) {
        return INVALID_ADDRESS;
    }
    return it->second;
}

void LiftedFunction::add_covered_address(Address addr) {
    // Keep sorted for binary search
    auto pos = std::lower_bound(covered_addresses_.begin(), covered_addresses_.end(), addr);
    if (pos == covered_addresses_.end() || *pos != addr) {
        covered_addresses_.insert(pos, addr);
    }
}

void LiftedFunction::set_status(LiftStatus s) noexcept {
    status_ = s;
    // Clear error on non-error status
    if (s != LiftStatus::Error) {
        error_.clear();
    }
}

void LiftedFunction::set_error(std::string msg) {
    status_ = LiftStatus::Error;
    error_ = std::move(msg);
}

} // namespace picanha::lift
