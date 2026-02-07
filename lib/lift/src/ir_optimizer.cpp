#include <picanha/lift/ir_optimizer.hpp>
#include <picanha/lift/lifted_function.hpp>

#include <llvm/IR/Module.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Scalar/Reassociate.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/Scalar/SROA.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/ADCE.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
#include <llvm/Transforms/Scalar/LoopUnrollPass.h>
#include <llvm/Transforms/Scalar/LICM.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/LoopAnalysisManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Optimizer.h>

namespace picanha::lift {

IROptimizer::IROptimizer(const remill::Arch* arch)
    : arch_(arch)
{
}

IROptimizer::~IROptimizer() = default;

bool IROptimizer::optimize(LiftedFunction& lifted, OptimizationLevel level) {
    if (!lifted.module()) {
        return false;
    }

    try {
        // Run optimization passes on the module
        run_optimization_passes(*lifted.module(), level);

        // Regenerate IR text - only for the target function
        lifted.invalidate_ir_cache();
        std::string ir_text = get_function_ir_text(*lifted.module(), lifted.name());
        lifted.set_optimized_ir(level, std::move(ir_text));

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::unique_ptr<llvm::Module> IROptimizer::clone_and_optimize(
    const llvm::Module& original,
    OptimizationLevel level
) {
    // Clone the module
    auto cloned = llvm::CloneModule(original);
    if (!cloned) {
        return nullptr;
    }

    try {
        run_optimization_passes(*cloned, level);
        return cloned;
    } catch (const std::exception&) {
        return nullptr;
    }
}

void IROptimizer::run_optimization_passes(llvm::Module& module, OptimizationLevel level) {
    if (level == OptimizationLevel::O0) {
        // No optimization
        return;
    }

    // Use LLVM's new pass manager
    llvm::LoopAnalysisManager LAM;
    llvm::FunctionAnalysisManager FAM;
    llvm::CGSCCAnalysisManager CGAM;
    llvm::ModuleAnalysisManager MAM;

    llvm::PassBuilder PB;

    // Register analysis passes
    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    // Get the optimization pipeline based on level
    llvm::ModulePassManager MPM;

    switch (level) {
        case OptimizationLevel::O1:
            MPM = PB.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O1);
            break;
        case OptimizationLevel::O2:
            MPM = PB.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O2);
            break;
        case OptimizationLevel::O3:
            MPM = PB.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O3);
            break;
        default:
            return;
    }

    // Run the optimization pipeline
    MPM.run(module, MAM);
}

std::string IROptimizer::get_ir_text(const llvm::Module& module) const {
    std::string ir_text;
    llvm::raw_string_ostream os(ir_text);
    module.print(os, nullptr);
    return ir_text;
}

std::string IROptimizer::get_function_ir_text(const llvm::Module& module, const std::string& func_name) const {
    std::string ir_text;
    llvm::raw_string_ostream os(ir_text);

    // Find the target function
    const llvm::Function* target = nullptr;
    for (const auto& fn : module.functions()) {
        if (!fn.isDeclaration()) {
            // Match exact name or name with suffix (e.g., sub_140001000.1)
            if (fn.getName() == func_name || fn.getName().starts_with(func_name + ".")) {
                target = &fn;
                break;
            }
        }
    }

    // If not found by name, try to find by address in name
    if (!target) {
        for (const auto& fn : module.functions()) {
            if (!fn.isDeclaration() && fn.getName().starts_with("sub_")) {
                target = &fn;
                break;
            }
        }
    }

    if (target) {
        // Print just the target function
        target->print(os, nullptr);
    } else {
        // Fallback: print all non-declaration functions (but not declarations)
        for (const auto& fn : module.functions()) {
            if (!fn.isDeclaration()) {
                fn.print(os, nullptr);
                os << "\n";
            }
        }
    }

    return ir_text;
}

} // namespace picanha::lift
