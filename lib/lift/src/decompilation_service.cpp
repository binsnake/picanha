#include <picanha/lift/decompilation_service.hpp>
#include <picanha/lift/lifting_context.hpp>
#include <picanha/lift/lifted_function.hpp>

#include <llvm/IR/Module.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/IPO/AlwaysInliner.h>
#include <llvm/Transforms/IPO/GlobalDCE.h>
#include <llvm/Transforms/Scalar/SROA.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/DeadStoreElimination.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Scalar/Reassociate.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Metadata.h>

#ifdef PICANHA_ENABLE_DECOMPILER
#include <rellic/Decompiler.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/PrettyPrinter.h>
#include <clang/Frontend/ASTUnit.h>
#endif

#include <sstream>
#include <format>
#include <vector>

namespace picanha::lift {

// Comprehensive simplification of remill intrinsics
// This replaces flag computations, memory intrinsics, and other remill calls
static void simplifyRemillIntrinsics(llvm::Module& module) {
    std::vector<llvm::CallInst*> to_simplify;
    std::vector<llvm::StoreInst*> pc_stores_to_remove;

    llvm::errs() << "[simplifyRemillIntrinsics] Starting pass on module\n";

    // Collect all remill intrinsic calls
    for (auto& func : module.functions()) {
        if (func.isDeclaration()) continue;

        llvm::errs() << "[simplifyRemillIntrinsics] Scanning function: " << func.getName() << "\n";

        for (auto& bb : func) {
            for (auto& inst : bb) {
                if (auto* call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
                    llvm::Function* callee = call->getCalledFunction();
                    if (!callee) {
                        // Try to get name from called operand for indirect calls
                        if (auto* calledValue = call->getCalledOperand()) {
                            if (calledValue->hasName()) {
                                auto name = calledValue->getName();
                                llvm::errs() << "[simplifyRemillIntrinsics] Found indirect call to: " << name << "\n";
                                if (name.starts_with("__remill_") || name.starts_with("llvm_ctpop_")) {
                                    to_simplify.push_back(call);
                                }
                            }
                        }
                        continue;
                    }
                    auto name = callee->getName();
                    if (name.starts_with("__remill_") || name.starts_with("llvm_ctpop_")) {
                        llvm::errs() << "[simplifyRemillIntrinsics] Found call to: " << name << "\n";
                        to_simplify.push_back(call);
                    }
                }
                // Collect stores to PC/NEXT_PC for removal
                if (auto* store = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
                    if (auto* alloca = llvm::dyn_cast<llvm::AllocaInst>(store->getPointerOperand())) {
                        auto name = alloca->getName();
                        if (name == "NEXT_PC" || name == "PC") {
                            pc_stores_to_remove.push_back(store);
                        }
                    }
                }
            }
        }
    }

    llvm::errs() << "[simplifyRemillIntrinsics] Found " << to_simplify.size() << " calls to simplify\n";

    // Process intrinsic calls
    for (auto* call : to_simplify) {
        auto* callee = call->getCalledFunction();
        if (!callee) continue;
        auto name = callee->getName();

        // Flag computation intrinsics - return first argument (the condition)
        if (name.starts_with("__remill_flag_computation_")) {
            if (call->arg_size() > 0) {
                llvm::errs() << "[simplifyRemillIntrinsics] Simplifying: " << name << "\n";
                auto* cond = call->getArgOperand(0);
                if (cond->getType() != call->getType()) {
                    auto* cast = llvm::CastInst::CreateZExtOrBitCast(
                        cond, call->getType(), "", call);
                    call->replaceAllUsesWith(cast);
                } else {
                    call->replaceAllUsesWith(cond);
                }
                call->eraseFromParent();
            }
            continue;
        }

        // Compare intrinsics - return first argument (the condition)
        if (name.starts_with("__remill_compare_")) {
            if (call->arg_size() > 0) {
                llvm::errs() << "[simplifyRemillIntrinsics] Simplifying: " << name << "\n";
                auto* cond = call->getArgOperand(0);
                if (cond->getType() != call->getType()) {
                    auto* cast = llvm::CastInst::CreateZExtOrBitCast(
                        cond, call->getType(), "", call);
                    call->replaceAllUsesWith(cast);
                } else {
                    call->replaceAllUsesWith(cond);
                }
                call->eraseFromParent();
            }
            continue;
        }

        // Undefined values - replace with 0
        if (name.starts_with("__remill_undefined_")) {
            llvm::errs() << "[simplifyRemillIntrinsics] Simplifying: " << name << "\n";
            auto* zero = llvm::Constant::getNullValue(call->getType());
            call->replaceAllUsesWith(zero);
            call->eraseFromParent();
            continue;
        }

        // Memory read intrinsics - replace with load
        // __remill_read_memory_N(mem, addr) -> *(intN*)addr
        if (name.starts_with("__remill_read_memory_")) {
            if (call->arg_size() >= 2) {
                llvm::errs() << "[simplifyRemillIntrinsics] Simplifying: " << name << "\n";
                auto* addr = call->getArgOperand(1);
                auto* result_type = call->getType();
                auto* ptr_type = llvm::PointerType::getUnqual(result_type);
                auto* ptr = new llvm::IntToPtrInst(addr, ptr_type, "", call);
                auto* load = new llvm::LoadInst(result_type, ptr, "", call);
                call->replaceAllUsesWith(load);
                call->eraseFromParent();
            }
            continue;
        }

        // Memory write intrinsics - replace with store, return memory arg
        // __remill_write_memory_N(mem, addr, val) -> *(intN*)addr = val; return mem
        if (name.starts_with("__remill_write_memory_")) {
            if (call->arg_size() >= 3) {
                llvm::errs() << "[simplifyRemillIntrinsics] Simplifying: " << name << "\n";
                auto* mem = call->getArgOperand(0);
                auto* addr = call->getArgOperand(1);
                auto* val = call->getArgOperand(2);
                auto* val_type = val->getType();
                auto* ptr_type = llvm::PointerType::getUnqual(val_type);
                auto* ptr = new llvm::IntToPtrInst(addr, ptr_type, "", call);
                new llvm::StoreInst(val, ptr, call);
                call->replaceAllUsesWith(mem);
                call->eraseFromParent();
            }
            continue;
        }

        // llvm_ctpop - parity computation, replace with 0 (not usually needed)
        if (name.starts_with("llvm_ctpop_")) {
            llvm::errs() << "[simplifyRemillIntrinsics] Simplifying: " << name << "\n";
            auto* zero = llvm::Constant::getNullValue(call->getType());
            call->replaceAllUsesWith(zero);
            call->eraseFromParent();
            continue;
        }

        // __remill_error, __remill_missing_block - leave as-is
    }

    // Remove PC stores (these are just bookkeeping, not needed in decompiled code)
    for (auto* store : pc_stores_to_remove) {
        store->eraseFromParent();
    }

    llvm::errs() << "[simplifyRemillIntrinsics] Pass complete\n";
}

// Spread PC metadata to all instructions in a function before inlining
// This attaches !insn_pc metadata to instructions so we can track origin after inlining
static void spreadPCMetadata(llvm::Module& module) {
    auto& ctx = module.getContext();
    unsigned md_kind = ctx.getMDKindID("insn_pc");

    for (auto& func : module.functions()) {
        if (func.isDeclaration()) continue;

        // Track the current PC value for this basic block
        for (auto& bb : func) {
            uint64_t current_pc = 0;
            bool found_pc = false;

            // First pass: find PC value stored in this block
            // Look for stores to NEXT_PC or PC from constant values
            for (auto& inst : bb) {
                if (auto* store = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
                    // Check if storing to NEXT_PC or PC
                    auto* ptr = store->getPointerOperand();
                    if (ptr->getName() == "NEXT_PC" || ptr->getName() == "PC") {
                        // Try to get the constant value being stored
                        if (auto* ci = llvm::dyn_cast<llvm::ConstantInt>(store->getValueOperand())) {
                            current_pc = ci->getZExtValue();
                            found_pc = true;
                        } else if (auto* add = llvm::dyn_cast<llvm::BinaryOperator>(store->getValueOperand())) {
                            // Handle pattern: %3 = add i64 %2, 3 (PC + instruction size)
                            if (add->getOpcode() == llvm::Instruction::Add) {
                                if (auto* ci = llvm::dyn_cast<llvm::ConstantInt>(add->getOperand(1))) {
                                    // This is the next PC, but we want the instruction that generated it
                                    // We'll use this PC minus the offset as a hint
                                    current_pc = ci->getZExtValue();
                                    found_pc = true;
                                }
                            }
                        }
                    }
                }
            }

            // Second pass: attach metadata to all instructions if we found a PC
            if (found_pc && current_pc != 0) {
                auto* pc_md = llvm::ConstantAsMetadata::get(
                    llvm::ConstantInt::get(llvm::Type::getInt64Ty(ctx), current_pc));
                auto* md_node = llvm::MDNode::get(ctx, pc_md);

                for (auto& inst : bb) {
                    inst.setMetadata(md_kind, md_node);
                }
            }
        }
    }
}

DecompilationService::DecompilationService(LiftingContext* context)
    : context_(context)
{
}

DecompilationService::~DecompilationService() = default;

bool DecompilationService::is_available() noexcept {
#ifdef PICANHA_ENABLE_DECOMPILER
    return true;
#else
    return false;
#endif
}

DecompilationResult DecompilationService::decompile(
    llvm::Module* module,
    const DecompilationConfig& config)
{
    DecompilationResult result;

#ifdef PICANHA_ENABLE_DECOMPILER
    if (!module) {
        result.error_message = "Module is null";
        last_error_ = result.error_message;
        return result;
    }

    try {
        // Clone the module since Rellic takes ownership
        auto cloned = llvm::CloneModule(*module);
        if (!cloned) {
            result.error_message = "Failed to clone module";
            last_error_ = result.error_message;
            return result;
        }

        // Mark all functions as external to prevent Rellic's passes from removing them
        for (auto& fn : cloned->functions()) {
            if (!fn.isDeclaration()) {
                fn.setLinkage(llvm::GlobalValue::ExternalLinkage);
            }
        }

        // Set up decompilation options
        rellic::DecompilationOptions options;
        options.lower_switches = config.lower_switches;
        options.remove_phi_nodes = config.remove_phi_nodes;

        // Decompile
        auto decomp_result = rellic::Decompile(std::move(cloned), std::move(options));

        if (!decomp_result.Succeeded()) {
            auto error = decomp_result.TakeError();
            result.error_message = error.message;
            last_error_ = result.error_message;
            return result;
        }

        // Get the result
        auto value = decomp_result.TakeValue();

        // Convert AST to C code string
        if (value.ast) {
            std::string code;
            llvm::raw_string_ostream os(code);

            auto& ast_context = value.ast->getASTContext();
            auto* tu = ast_context.getTranslationUnitDecl();

            // Print all declarations (including structs, typedefs, and functions)
            clang::PrintingPolicy policy(ast_context.getLangOpts());
            policy.FullyQualifiedName = false;
            policy.SuppressSpecifiers = false;
            policy.IncludeNewlines = true;

            for (auto* decl : tu->decls()) {
                // Skip implicit declarations
                if (decl->isImplicit()) continue;

                decl->print(os, policy);
                os << "\n\n";
            }

            os.flush();
            result.code = std::move(code);
            result.success = true;
        } else {
            result.error_message = "Decompilation produced no AST";
            last_error_ = result.error_message;
        }

    } catch (const std::exception& e) {
        result.error_message = std::string("Decompilation exception: ") + e.what();
        last_error_ = result.error_message;
    }

#else
    result.error_message = "Decompiler not available (PICANHA_ENABLE_DECOMPILER is OFF)";
    last_error_ = result.error_message;
#endif

    return result;
}

DecompilationResult DecompilationService::decompile_function(
    const LiftedFunction& func,
    const DecompilationConfig& config)
{
    return decompile(func.module(), config);
}

DecompilationResult DecompilationService::decompile_function_copy(
    const LiftedFunction& func,
    const DecompilationConfig& config)
{
    llvm::errs() << "[decompile_function_copy] ENTRY - Function: " << func.name() << "\n";

    DecompilationResult result;

#ifdef PICANHA_ENABLE_DECOMPILER
    llvm::errs() << "[decompile_function_copy] PICANHA_ENABLE_DECOMPILER is ON\n";
    if (!func.module()) {
        result.error_message = "Function has no module";
        last_error_ = result.error_message;
        return result;
    }

    try {
        // Clone the module
        auto cloned = llvm::CloneModule(*func.module());
        if (!cloned) {
            result.error_message = "Failed to clone module";
            last_error_ = result.error_message;
            return result;
        }

        // Find the main lifted trace function (should be the one matching our function name)
        // The lifted function name is typically "sub_XXXXXXX" for the entry address
        std::string target_name = func.name();

        llvm::Function* target_func = nullptr;
        for (auto& fn : cloned->functions()) {
            if (!fn.isDeclaration()) {
                // Check if this is our target function (exact match or starts with our name)
                if (fn.getName() == target_name ||
                    fn.getName().starts_with(target_name + ".")) {
                    fn.setLinkage(llvm::GlobalValue::ExternalLinkage);
                    target_func = &fn;
                }
            }
        }

        if (!target_func) {
            // Fallback: look for any sub_XXXXXXX where XXXXXXX matches our entry address
            std::string addr_hex = std::format("{:X}", func.entry_address());
            for (auto& fn : cloned->functions()) {
                if (!fn.isDeclaration() && fn.getName().contains(addr_hex)) {
                    fn.setLinkage(llvm::GlobalValue::ExternalLinkage);
                    target_func = &fn;
                    break;
                }
            }
        }

        if (!target_func) {
            result.error_message = "Could not find target function in module";
            last_error_ = result.error_message;
            return result;
        }

        // Mark all semantic handlers for inlining
        for (auto& fn : cloned->functions()) {
            if (!fn.isDeclaration() && &fn != target_func) {
                // Remove attributes that block inlining
                fn.removeFnAttr(llvm::Attribute::NoInline);
                fn.removeFnAttr(llvm::Attribute::OptimizeNone);
                fn.addFnAttr(llvm::Attribute::AlwaysInline);
                fn.setLinkage(llvm::GlobalValue::InternalLinkage);
            }
        }
        // Also clean up target function
        target_func->removeFnAttr(llvm::Attribute::NoInline);
        target_func->removeFnAttr(llvm::Attribute::OptimizeNone);

        // Spread PC metadata to all instructions before inlining
        // This allows us to track which original instruction each piece of IR came from
        spreadPCMetadata(*cloned);

        // Run inlining and optimization passes
        {
            llvm::PassBuilder PB;
            llvm::ModulePassManager MPM;
            llvm::ModuleAnalysisManager MAM;
            llvm::FunctionAnalysisManager FAM;
            llvm::LoopAnalysisManager LAM;
            llvm::CGSCCAnalysisManager CGAM;

            PB.registerModuleAnalyses(MAM);
            PB.registerCGSCCAnalyses(CGAM);
            PB.registerFunctionAnalyses(FAM);
            PB.registerLoopAnalyses(LAM);
            PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

            // Inline all the semantic handlers
            MPM.addPass(llvm::AlwaysInlinerPass());

            MPM.run(*cloned, MAM);
        }

        // Simplify remill flag intrinsics after inlining
        simplifyRemillIntrinsics(*cloned);

        // Run optimization passes to clean up after inlining
        {
            llvm::PassBuilder PB;
            llvm::ModulePassManager MPM;
            llvm::ModuleAnalysisManager MAM;
            llvm::FunctionAnalysisManager FAM;
            llvm::LoopAnalysisManager LAM;
            llvm::CGSCCAnalysisManager CGAM;

            PB.registerModuleAnalyses(MAM);
            PB.registerCGSCCAnalyses(CGAM);
            PB.registerFunctionAnalyses(FAM);
            PB.registerLoopAnalyses(LAM);
            PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

            // Run optimization passes to clean up
            // Run multiple iterations for better optimization
            for (int i = 0; i < 2; i++) {
                llvm::FunctionPassManager FPM;
                FPM.addPass(llvm::PromotePass());       // mem2reg - promote allocas to SSA
                FPM.addPass(llvm::SROAPass(llvm::SROAOptions::ModifyCFG));  // Scalar Replacement of Aggregates
                FPM.addPass(llvm::EarlyCSEPass(true));  // Common Subexpression Elimination (with MemorySSA)
                FPM.addPass(llvm::ReassociatePass());   // Reassociate expressions
                FPM.addPass(llvm::InstCombinePass());   // Instruction combining
                FPM.addPass(llvm::GVNPass());           // Global Value Numbering
                FPM.addPass(llvm::SimplifyCFGPass());   // Simplify control flow
                FPM.addPass(llvm::DCEPass());           // Dead Code Elimination
                FPM.addPass(llvm::DSEPass());           // Dead Store Elimination
                MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(FPM)));
            }

            // Remove dead functions after inlining
            MPM.addPass(llvm::GlobalDCEPass());

            MPM.run(*cloned, MAM);
        }

        // Delete remaining non-target function bodies for faster decompilation
        std::vector<llvm::Function*> to_delete;
        for (auto& fn : cloned->functions()) {
            if (!fn.isDeclaration() && &fn != target_func) {
                to_delete.push_back(&fn);
            }
        }
        for (auto* fn : to_delete) {
            fn->deleteBody();
        }

        // Set up decompilation options
        rellic::DecompilationOptions options;
        options.lower_switches = config.lower_switches;
        options.remove_phi_nodes = config.remove_phi_nodes;

        // Decompile
        auto decomp_result = rellic::Decompile(std::move(cloned), std::move(options));

        if (!decomp_result.Succeeded()) {
            auto error = decomp_result.TakeError();
            result.error_message = error.message;
            last_error_ = result.error_message;
            return result;
        }

        // Get the result
        auto value = decomp_result.TakeValue();

        // Convert AST to C code string
        if (value.ast) {
            std::string code;
            llvm::raw_string_ostream os(code);

            auto& ast_context = value.ast->getASTContext();
            auto* tu = ast_context.getTranslationUnitDecl();

            // Print all declarations (including structs, typedefs, and functions)
            clang::PrintingPolicy policy(ast_context.getLangOpts());
            policy.FullyQualifiedName = false;
            policy.SuppressSpecifiers = false;
            policy.IncludeNewlines = true;

            for (auto* decl : tu->decls()) {
                // Skip implicit declarations
                if (decl->isImplicit()) continue;

                decl->print(os, policy);
                os << "\n\n";
            }

            os.flush();
            result.code = std::move(code);
            result.success = true;
        } else {
            result.error_message = "Decompilation produced no AST";
            last_error_ = result.error_message;
        }

    } catch (const std::exception& e) {
        result.error_message = std::string("Decompilation exception: ") + e.what();
        last_error_ = result.error_message;
    }

#else
    llvm::errs() << "[decompile_function_copy] PICANHA_ENABLE_DECOMPILER is OFF!\n";
    result.error_message = "Decompiler not available (PICANHA_ENABLE_DECOMPILER is OFF)";
    last_error_ = result.error_message;
#endif

    llvm::errs() << "[decompile_function_copy] EXIT\n";
    return result;
}

} // namespace picanha::lift
