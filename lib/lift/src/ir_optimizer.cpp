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
#include <llvm/Passes/OptimizationLevel.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/MC/TargetRegistry.h>
#include <llvm/Target/TargetMachine.h>

#include <spdlog/spdlog.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/DeadStoreEliminator.h>
#include <remill/BC/Optimizer.h>

#include <mutex>

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

static std::once_flag s_target_init_flag;

static llvm::TargetMachine* create_target_machine(const llvm::Module& module) {
    std::call_once(s_target_init_flag, [] {
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86Target();
        LLVMInitializeX86TargetMC();
        LLVMInitializeX86AsmPrinter();
        LLVMInitializeX86AsmParser();
    });

    auto triple = module.getTargetTriple();
    if (triple.empty()) triple = "x86_64-pc-windows-msvc";

    std::string error;
    auto* target = llvm::TargetRegistry::lookupTarget(triple, error);
    if (!target) {
        spdlog::warn("Could not look up target for '{}': {}", triple, error);
        return nullptr;
    }

    return target->createTargetMachine(
        triple, "generic", "",
        llvm::TargetOptions(), std::nullopt);
}

void IROptimizer::run_optimization_passes(llvm::Module& module, OptimizationLevel level) {
    if (level == OptimizationLevel::O0) {
        return;
    }

    // Create a TargetMachine so PassBuilder registers TargetTransformInfo (TTI)
    // and TargetLibraryInfo (TLI). Without these, LLVM's cost models are overly
    // conservative and DSE/GVN/inlining produce significantly worse code.
    std::unique_ptr<llvm::TargetMachine> TM(create_target_machine(module));
    if (TM) {
        module.setDataLayout(TM->createDataLayout());
        spdlog::info("Optimizer: using TargetMachine for triple '{}', data layout '{}'",
                     module.getTargetTriple(), module.getDataLayoutStr());
    } else {
        spdlog::warn("Optimizer: no TargetMachine — optimization will be degraded");
    }

    llvm::LoopAnalysisManager LAM;
    llvm::FunctionAnalysisManager FAM;
    llvm::CGSCCAnalysisManager CGAM;
    llvm::ModuleAnalysisManager MAM;

    llvm::PassBuilder PB(TM.get());

    PB.registerModuleAnalyses(MAM);
    PB.registerCGSCCAnalyses(CGAM);
    PB.registerFunctionAnalyses(FAM);
    PB.registerLoopAnalyses(LAM);
    PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

    // McSema-style optimization pipeline for lifted bitcode
    // This ordering is tuned for remill-generated IR
    llvm::ModulePassManager MPM;

    // Build the pipeline based on optimization level
    llvm::OptimizationLevel opt_level;
    switch (level) {
        case OptimizationLevel::O1:
            opt_level = llvm::OptimizationLevel::O1;
            break;
        case OptimizationLevel::O2:
            opt_level = llvm::OptimizationLevel::O2;
            break;
        case OptimizationLevel::O3:
            opt_level = llvm::OptimizationLevel::O3;
            break;
        default:
            return;
    }

    // Use the standard pipeline but with additional scalar optimizations
    // that are particularly useful for lifted code
    MPM = PB.buildPerModuleDefaultPipeline(opt_level);

    // Add additional passes after the standard pipeline that help with lifted code
    // These target common patterns in remill-generated IR
    
    // Run function-level optimizations to clean up after the module pipeline
    llvm::FunctionPassManager FPM;
    FPM.addPass(llvm::createEarlyCSEPass(true));           // Common subexpression elimination
    FPM.addPass(llvm::createDeadCodeEliminationPass());     // Dead code elimination
    FPM.addPass(llvm::createSinkingPass());                // Move instructions down
    FPM.addPass(llvm::createGVNPass());                    // Global value numbering
    FPM.addPass(llvm::createEarlyCSEPass(true));           // CSE after GVN
    FPM.addPass(llvm::createSROAPass());                    // Scalar replacement of aggregates
    FPM.addPass(llvm::createPromoteMemoryToRegisterPass()); // Mem2reg
    FPM.addPass(llvm::createCFGSimplificationPass());       // Simplify CFG
    FPM.addPass(llvm::createSinkingPass());                // Sink again after simplifications
    FPM.addPass(llvm::createCFGSimplificationPass());       // Simplify CFG again

    MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(FPM)));

    // Run the pipeline
    MPM.run(module, MAM);

    // Run architecture-aware dead store elimination for state structure
    // This removes stores to the State structure that are never read
    try {
        auto slots = remill::StateSlotsForArch(arch_);
        if (!slots.empty()) {
            remill::RemoveDeadStores(arch_, &module, nullptr, slots);
        }
    } catch (const std::exception& e) {
        spdlog::warn("DeadStoreEliminator failed: {}", e.what());
    }
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
