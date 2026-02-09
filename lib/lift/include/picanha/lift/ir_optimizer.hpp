#pragma once

#include <picanha/lift/types.hpp>
#include <memory>
#include <string>

// Forward declarations
namespace llvm {
class Module;
} // namespace llvm

namespace remill {
class Arch;
} // namespace remill

namespace picanha::lift {

class LiftedFunction;

// LLVM optimization pass runner
class IROptimizer {
public:
    explicit IROptimizer(const remill::Arch* arch);
    ~IROptimizer();

    // Run optimization passes on a lifted function's module
    // Modifies the module in-place
    // Returns true on success
    bool optimize(LiftedFunction& lifted, OptimizationLevel level);

    // Clone a module and optimize the clone
    // Preserves the original module
    // Returns the optimized clone (or nullptr on failure)
    [[nodiscard]] std::unique_ptr<llvm::Module> clone_and_optimize(
        const llvm::Module& original,
        OptimizationLevel level
    );

    // Get the IR text of an optimized module
    [[nodiscard]] std::string get_ir_text(const llvm::Module& module) const;

    // Get the IR text of just a specific function
    [[nodiscard]] std::string get_function_ir_text(const llvm::Module& module, const std::string& func_name) const;

    // Run optimization passes on a module directly
    void run_optimization_passes(llvm::Module& module, OptimizationLevel level);

private:

    const remill::Arch* arch_;
};

} // namespace picanha::lift
