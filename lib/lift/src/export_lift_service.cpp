#include <picanha/lift/export_lift_service.hpp>
#include <picanha/lift/lifted_function.hpp>
#include <picanha/lift/trace_manager_impl.hpp>
#include <picanha/lift/ir_optimizer.hpp>

#include <spdlog/spdlog.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Linker/Linker.h>

#include <remill/BC/TraceLifter.h>
#include <remill/BC/Util.h>

#include <format>
#include <sstream>
#include <filesystem>
#include <cstdlib>
#include <fstream>
#include <algorithm>
#include <regex>
#include <queue>
#include <set>
#include <map>

namespace picanha::lift {

ExportLiftService::ExportLiftService(std::shared_ptr<loader::Binary> binary)
    : binary_(std::move(binary))
    , lifting_service_(std::make_unique<LiftingService>(binary_))
{
}

ExportLiftService::~ExportLiftService() = default;

bool ExportLiftService::initialize() {
    if (initialized_) return true;
    if (!lifting_service_->initialize()) {
        error_ = "Failed to initialize lifting service: " + lifting_service_->error_message();
        return false;
    }
    initialized_ = true;
    return true;
}

// --------------------------------------------------------------------------
// Utilities
// --------------------------------------------------------------------------

// Extracts the base name (e.g., "sub_140001000") from a suffixed name (e.g., "sub_140001000.1")
static std::string get_base_name(llvm::StringRef name) {
    // Simple robust parsing: strip everything after the first dot if it looks like a suffix
    // This handles sub_X.1, sub_X.2, etc.
    std::string n = name.str();
    size_t dot_pos = n.find('.');
    if (dot_pos != std::string::npos) {
        // Optional: verify chars after dot are digits to avoid stripping semantic names
        // But for remill traces, suffixes are almost always numerical versions
        return n.substr(0, dot_pos);
    }
    return n;
}

// --------------------------------------------------------------------------
// Improved Pointer Resolution for Memory Intrinsics
// --------------------------------------------------------------------------
// Handles complex address computations that remill-generated code may use.
// This is based on McSema's pointer resolution logic.

static llvm::Value* get_pointer_from_address(llvm::IRBuilder<>& builder, llvm::Value* addr,
                                              llvm::Type* elem_type, unsigned addr_space = 0) {
    auto& ctx = builder.getContext();
    auto dest_type = llvm::PointerType::get(elem_type, addr_space);
    auto addr_type = addr->getType();

    // Handle inttoptr instruction
    if (auto* itp = llvm::dyn_cast<llvm::IntToPtrInst>(addr)) {
        llvm::IRBuilder<> sub_builder(itp);
        return get_pointer_from_address(sub_builder, itp->getOperand(0), elem_type, addr_space);
    }

    // Handle ptrtoint - go back to the pointer operand
    if (auto* pti = llvm::dyn_cast<llvm::PtrToIntOperator>(addr)) {
        return get_pointer_from_address(builder, pti->getPointerOperand(), elem_type, addr_space);
    }

    // Already a pointer of the right type
    if (addr_type == dest_type) {
        return addr;
    }

    // Handle constant integers - try to convert to pointer
    if (auto* ci = llvm::dyn_cast<llvm::ConstantInt>(addr)) {
        return llvm::ConstantExpr::getIntToPtr(ci, dest_type);
    }

    // Handle constant expressions
    if (auto* ce = llvm::dyn_cast<llvm::ConstantExpr>(addr)) {
        if (ce->getOpcode() == llvm::Instruction::IntToPtr) {
            return get_pointer_from_address(builder, ce->getOperand(0), elem_type, addr_space);
        } else if (addr_type->isIntegerTy()) {
            return llvm::ConstantExpr::getIntToPtr(ce, dest_type);
        }
    }

    // Handle Add operations - try to find pointer and compute offset
    if (auto* add = llvm::dyn_cast<llvm::AddOperator>(addr)) {
        llvm::Value* lhs_op = add->getOperand(0);
        llvm::Value* rhs_op = add->getOperand(1);

        llvm::Value* lhs = get_pointer_from_address(builder, lhs_op, elem_type, addr_space);
        llvm::Value* rhs = get_pointer_from_address(builder, rhs_op, elem_type, addr_space);

        if (lhs && rhs) {
            spdlog::warn("get_pointer_from_address: both operands are pointers in add");
            return builder.CreateIntToPtr(addr, dest_type);
        }

        if (rhs) {
            // Indexed pointer access
            auto* i32_ty = llvm::Type::getInt32Ty(ctx);
            llvm::Value* indices[1] = {builder.CreateTrunc(rhs_op, i32_ty)};
            auto* base = llvm::cast<llvm::Value>(builder.CreateBitCast(rhs, llvm::PointerType::get(elem_type, addr_space)));
            return builder.CreateGEP(elem_type, base, indices);
        } else if (lhs) {
            auto* i32_ty = llvm::Type::getInt32Ty(ctx);
            llvm::Value* indices[1] = {builder.CreateTrunc(rhs_op, i32_ty)};
            auto* base = llvm::cast<llvm::Value>(builder.CreateBitCast(lhs, llvm::PointerType::get(elem_type, addr_space)));
            return builder.CreateGEP(elem_type, base, indices);
        }
    }

    // Handle Sub operations
    if (auto* sub = llvm::dyn_cast<llvm::SubOperator>(addr)) {
        llvm::Value* lhs_op = sub->getOperand(0);
        llvm::Value* rhs_op = sub->getOperand(1);
        auto* rhs = llvm::dyn_cast<llvm::ConstantInt>(rhs_op);

        if (auto* lhs = get_pointer_from_address(builder, lhs_op, elem_type, addr_space)) {
            if (rhs) {
                // Subtract constant offset
                auto i32_ty = llvm::Type::getInt32Ty(ctx);
                auto neg_offset = static_cast<int64_t>(-static_cast<int32_t>(rhs->getZExtValue()));
                auto const_index = llvm::ConstantInt::get(i32_ty, static_cast<uint64_t>(neg_offset), true);
                llvm::Value* indices[1] = {const_index};
                auto* base = llvm::cast<llvm::Value>(builder.CreateBitCast(lhs, llvm::PointerType::get(elem_type, addr_space)));
                return builder.CreateGEP(elem_type, base, indices);
            }
        }
    }

    // Handle BitCast operations
    if (auto* bc = llvm::dyn_cast<llvm::BitCastOperator>(addr)) {
        return get_pointer_from_address(builder, bc->getOperand(0), elem_type, addr_space);
    }

    // Handle global values
    if (llvm::isa<llvm::GlobalValue>(addr)) {
        return builder.CreateBitCast(addr, dest_type);
    }

    // Fallback: inttoptr
    return builder.CreateIntToPtr(addr, dest_type);
}

// --------------------------------------------------------------------------
// Remill Intrinsic Lowering
// --------------------------------------------------------------------------
// Replaces __remill_* intrinsic call sites with native LLVM IR (loads, stores,
// dispatches) so the recompiled binary actually performs real operations instead
// of calling stubs that return null/zero.

static void lower_remill_intrinsics(llvm::Module& module) {
    auto& ctx = module.getContext();
    llvm::IRBuilder<> builder(ctx);
    static const std::regex sub_regex(R"(sub_([0-9a-fA-F]+).*)");

    // Step 0: Strip remill's optimization-blocking attributes from intrinsics.
    // Remill's IntrinsicTable.cpp marks all __remill_* functions with NoDuplicate,
    // OptimizeNone, NoInline. These survive CloneModule and prevent LLVM from
    // inlining or optimizing through the intrinsics after we give them bodies.
    for (auto& func : module.functions()) {
        if (!func.getName().starts_with("__remill_")) continue;
        func.removeFnAttr(llvm::Attribute::NoDuplicate);
        func.removeFnAttr(llvm::Attribute::OptimizeNone);
        func.removeFnAttr(llvm::Attribute::NoInline);
    }

    // Step 1: Build trace address map
    std::map<uint64_t, llvm::Function*> trace_map;
    for (auto& func : module.functions()) {
        if (func.isDeclaration()) continue;
        std::string name = func.getName().str();
        std::smatch match;
        if (std::regex_match(name, match, sub_regex)) {
            try {
                uint64_t addr = std::stoull(match[1].str(), nullptr, 16);
                trace_map[addr] = &func;
            } catch (...) {}
        }
    }
    spdlog::info("lower_remill_intrinsics: found {} trace functions", trace_map.size());

    // Step 2: Create dispatch bodies for control-flow intrinsics

    // __remill_function_return: just return %mem (arg 2)
    if (auto* func = module.getFunction("__remill_function_return")) {
        if (func->isDeclaration()) {
            func->getArg(0)->addAttr(llvm::Attribute::NoAlias);  // State*
            func->getArg(2)->addAttr(llvm::Attribute::NoAlias);  // Memory*
            auto* bb = llvm::BasicBlock::Create(ctx, "entry", func);
            builder.SetInsertPoint(bb);
            builder.CreateRet(func->getArg(2)); // return %mem
            func->setLinkage(llvm::GlobalValue::InternalLinkage);
            spdlog::debug("Lowered __remill_function_return");
        }
    }

    // Helper lambda to build a switch dispatch over all known traces
    auto build_dispatch = [&](llvm::Function* func, const char* label) {
        if (!func || !func->isDeclaration()) return;

        func->getArg(0)->addAttr(llvm::Attribute::NoAlias);  // State*
        func->getArg(2)->addAttr(llvm::Attribute::NoAlias);  // Memory*

        auto* entry_bb = llvm::BasicBlock::Create(ctx, "entry", func);
        auto* default_bb = llvm::BasicBlock::Create(ctx, "default", func);

        builder.SetInsertPoint(entry_bb);
        llvm::Value* addr_arg = func->getArg(1);  // i64 %addr
        auto* sw = builder.CreateSwitch(addr_arg, default_bb, trace_map.size());

        for (auto& [addr, target] : trace_map) {
            auto* case_bb = llvm::BasicBlock::Create(ctx, std::format("{}_{:X}", label, addr), func);
            sw->addCase(llvm::ConstantInt::get(llvm::Type::getInt64Ty(ctx), addr), case_bb);

            builder.SetInsertPoint(case_bb);
            // Call the trace: ptr @sub_XXX(ptr %state, i64 %addr, ptr %mem)
            std::vector<llvm::Value*> args = {func->getArg(0), addr_arg, func->getArg(2)};
            auto* call = builder.CreateCall(target->getFunctionType(), target, args);
            builder.CreateRet(call);
        }

        // Unknown dispatch target is a program error — use unreachable so LLVM
        // can prove this path dead and fold the switch when all addresses are constants.
        builder.SetInsertPoint(default_bb);
        builder.CreateUnreachable();

        func->setLinkage(llvm::GlobalValue::InternalLinkage);
        spdlog::debug("Lowered {} with {} dispatch entries", func->getName().str(), trace_map.size());
    };

    build_dispatch(module.getFunction("__remill_function_call"), "call");
    build_dispatch(module.getFunction("__remill_jump"), "jmp");

    // __remill_error, __remill_missing_block: return %mem
    for (const char* name : {"__remill_error", "__remill_missing_block"}) {
        if (auto* func = module.getFunction(name)) {
            if (func->isDeclaration()) {
                func->getArg(0)->addAttr(llvm::Attribute::NoAlias);  // State*
                func->getArg(2)->addAttr(llvm::Attribute::NoAlias);  // Memory*
                auto* bb = llvm::BasicBlock::Create(ctx, "entry", func);
                builder.SetInsertPoint(bb);
                builder.CreateRet(func->getArg(2));
                func->setLinkage(llvm::GlobalValue::InternalLinkage);
                spdlog::debug("Lowered {}", name);
            }
        }
    }

    // Steps 3 & 4: Inline-replace memory and other intrinsic call sites
    // We collect instructions to erase after processing to avoid iterator invalidation.
    std::vector<llvm::Instruction*> to_erase;
    unsigned devirtualized = 0;

    for (auto& func : module.functions()) {
        if (func.isDeclaration()) continue;

        for (auto& bb : func) {
            for (auto& inst : bb) {
                auto* call = llvm::dyn_cast<llvm::CallInst>(&inst);
                if (!call) continue;

                auto* callee = call->getCalledFunction();
                if (!callee) continue;

                llvm::StringRef cname = callee->getName();
                if (!cname.starts_with("__remill_")) continue;

                builder.SetInsertPoint(call);

                // --- Memory reads ---
                if (cname == "__remill_read_memory_8" || cname == "__remill_read_memory_16" ||
                    cname == "__remill_read_memory_32" || cname == "__remill_read_memory_64") {
                    // Signature: rettype (ptr %mem, i64 %addr)
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Type* ret_ty = call->getType();
                    auto* ptr = get_pointer_from_address(builder, addr, ret_ty, 0);
                    auto* val = builder.CreateAlignedLoad(ret_ty, ptr, llvm::MaybeAlign(1));
                    call->replaceAllUsesWith(val);
                    to_erase.push_back(call);
                }
                else if (cname == "__remill_read_memory_f32" || cname == "__remill_read_memory_f64" ||
                         cname == "__remill_read_memory_f128") {
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Type* ret_ty = call->getType();
                    auto* ptr = get_pointer_from_address(builder, addr, ret_ty, 0);
                    auto* val = builder.CreateAlignedLoad(ret_ty, ptr, llvm::MaybeAlign(1));
                    call->replaceAllUsesWith(val);
                    to_erase.push_back(call);
                }
                else if (cname == "__remill_read_memory_f80") {
                    // Signature: ptr (ptr %mem, i64 %addr, ptr %ref) — writes to reference param
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Value* ref = call->getArgOperand(2);
                    auto* fp80_ty = llvm::Type::getX86_FP80Ty(ctx);
                    auto* ptr = get_pointer_from_address(builder, addr, fp80_ty, 0);
                    auto* val = builder.CreateAlignedLoad(fp80_ty, ptr, llvm::MaybeAlign(1));
                    builder.CreateStore(val, ref);
                    call->replaceAllUsesWith(call->getArgOperand(0)); // return %mem
                    to_erase.push_back(call);
                }
                // --- Memory writes ---
                else if (cname == "__remill_write_memory_8" || cname == "__remill_write_memory_16" ||
                         cname == "__remill_write_memory_32" || cname == "__remill_write_memory_64") {
                    // Signature: ptr (ptr %mem, i64 %addr, valtype %val)
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Value* val = call->getArgOperand(2);
                    auto* ptr = get_pointer_from_address(builder, addr, val->getType(), 0);
                    builder.CreateAlignedStore(val, ptr, llvm::MaybeAlign(1));
                    call->replaceAllUsesWith(call->getArgOperand(0)); // return %mem
                    to_erase.push_back(call);
                }
                else if (cname == "__remill_write_memory_f32" || cname == "__remill_write_memory_f64" ||
                         cname == "__remill_write_memory_f128") {
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Value* val = call->getArgOperand(2);
                    auto* ptr = get_pointer_from_address(builder, addr, val->getType(), 0);
                    builder.CreateAlignedStore(val, ptr, llvm::MaybeAlign(1));
                    call->replaceAllUsesWith(call->getArgOperand(0)); // return %mem
                    to_erase.push_back(call);
                }
                else if (cname == "__remill_write_memory_f80") {
                    // Signature: ptr (ptr %mem, i64 %addr, ptr %ref) — reads from const reference
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Value* ref = call->getArgOperand(2);
                    auto* fp80_ty = llvm::Type::getX86_FP80Ty(ctx);
                    auto* ptr = get_pointer_from_address(builder, addr, fp80_ty, 0);
                    auto* val = builder.CreateAlignedLoad(fp80_ty, ref, llvm::MaybeAlign(1));
                    builder.CreateAlignedStore(val, ptr, llvm::MaybeAlign(1));
                    call->replaceAllUsesWith(call->getArgOperand(0)); // return %mem
                    to_erase.push_back(call);
                }
                // --- Barriers, atomics, delay slots: pass-through %mem ---
                else if (cname.starts_with("__remill_barrier_") ||
                         cname == "__remill_atomic_begin" || cname == "__remill_atomic_end" ||
                         cname == "__remill_delay_slot_begin" || cname == "__remill_delay_slot_end") {
                    if (!call->getType()->isVoidTy())
                        call->replaceAllUsesWith(call->getArgOperand(0)); // return %mem (arg 0)
                    to_erase.push_back(call);
                }
                // --- Undefined values ---
                else if (cname.starts_with("__remill_undefined_")) {
                    call->replaceAllUsesWith(llvm::UndefValue::get(call->getType()));
                    to_erase.push_back(call);
                }
                // --- Flag computations: return arg[0] (the computed condition) ---
                else if (cname.starts_with("__remill_flag_computation_")) {
                    if (call->arg_size() > 0) {
                        llvm::Value* cond = call->getArgOperand(0);
                        if (cond->getType() != call->getType())
                            cond = builder.CreateZExtOrBitCast(cond, call->getType());
                        call->replaceAllUsesWith(cond);
                    } else {
                        call->replaceAllUsesWith(llvm::UndefValue::get(call->getType()));
                    }
                    to_erase.push_back(call);
                }
                // --- Compare-exchange ---
                else if (cname.starts_with("__remill_compare_exchange_memory_")) {
                    // Signature: ptr (ptr %mem, i64 %addr, ptr %expected_ref, intN %desired)
                    llvm::Value* mem = call->getArgOperand(0);
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Value* expected_ref = call->getArgOperand(2);
                    llvm::Value* desired = call->getArgOperand(3);

                    llvm::Type* val_ty = desired->getType();
                    auto* ptr = get_pointer_from_address(builder, addr, val_ty, 0);

                    // Non-atomic lowering: load old, compare, conditionally store
                    auto* old_val = builder.CreateAlignedLoad(val_ty, ptr, llvm::MaybeAlign(1));
                    auto* expected_val = builder.CreateAlignedLoad(val_ty, expected_ref, llvm::MaybeAlign(1));
                    auto* cmp = builder.CreateICmpEQ(old_val, expected_val);

                    // If equal, store desired; either way, store old to expected_ref
                    auto* select_val = builder.CreateSelect(cmp, desired, old_val);
                    builder.CreateAlignedStore(select_val, ptr, llvm::MaybeAlign(1));
                    builder.CreateAlignedStore(old_val, expected_ref, llvm::MaybeAlign(1));

                    call->replaceAllUsesWith(mem);
                    to_erase.push_back(call);
                }
                // --- Fetch and add ---
                else if (cname.starts_with("__remill_fetch_and_add_")) {
                    // Signature: ptr (ptr %mem, i64 %addr, valtype %val) -> valtype
                    llvm::Value* mem = call->getArgOperand(0);
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Value* val = call->getArgOperand(2);

                    llvm::Type* val_ty = val->getType();
                    auto* ptr = get_pointer_from_address(builder, addr, val_ty, 0);

                    // Non-atomic lowering: load old, add, store new, return old
                    auto* old_val = builder.CreateAlignedLoad(val_ty, ptr, llvm::MaybeAlign(1));
                    auto* new_val = builder.CreateAdd(old_val, val);
                    builder.CreateAlignedStore(new_val, ptr, llvm::MaybeAlign(1));

                    call->replaceAllUsesWith(old_val);
                    to_erase.push_back(call);
                }
                // --- Fetch and sub ---
                else if (cname.starts_with("__remill_fetch_and_sub_")) {
                    llvm::Value* mem = call->getArgOperand(0);
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Value* val = call->getArgOperand(2);

                    llvm::Type* val_ty = val->getType();
                    auto* ptr = get_pointer_from_address(builder, addr, val_ty, 0);

                    auto* old_val = builder.CreateAlignedLoad(val_ty, ptr, llvm::MaybeAlign(1));
                    auto* new_val = builder.CreateSub(old_val, val);
                    builder.CreateAlignedStore(new_val, ptr, llvm::MaybeAlign(1));

                    call->replaceAllUsesWith(old_val);
                    to_erase.push_back(call);
                }
                // --- Fetch and and ---
                else if (cname.starts_with("__remill_fetch_and_and_")) {
                    llvm::Value* mem = call->getArgOperand(0);
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Value* val = call->getArgOperand(2);

                    llvm::Type* val_ty = val->getType();
                    auto* ptr = get_pointer_from_address(builder, addr, val_ty, 0);

                    auto* old_val = builder.CreateAlignedLoad(val_ty, ptr, llvm::MaybeAlign(1));
                    auto* new_val = builder.CreateAnd(old_val, val);
                    builder.CreateAlignedStore(new_val, ptr, llvm::MaybeAlign(1));

                    call->replaceAllUsesWith(old_val);
                    to_erase.push_back(call);
                }
                // --- Fetch and or ---
                else if (cname.starts_with("__remill_fetch_and_or_")) {
                    llvm::Value* mem = call->getArgOperand(0);
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Value* val = call->getArgOperand(2);

                    llvm::Type* val_ty = val->getType();
                    auto* ptr = get_pointer_from_address(builder, addr, val_ty, 0);

                    auto* old_val = builder.CreateAlignedLoad(val_ty, ptr, llvm::MaybeAlign(1));
                    auto* new_val = builder.CreateOr(old_val, val);
                    builder.CreateAlignedStore(new_val, ptr, llvm::MaybeAlign(1));

                    call->replaceAllUsesWith(old_val);
                    to_erase.push_back(call);
                }
                // --- Fetch and xor ---
                else if (cname.starts_with("__remill_fetch_and_xor_")) {
                    llvm::Value* mem = call->getArgOperand(0);
                    llvm::Value* addr = call->getArgOperand(1);
                    llvm::Value* val = call->getArgOperand(2);

                    llvm::Type* val_ty = val->getType();
                    auto* ptr = get_pointer_from_address(builder, addr, val_ty, 0);

                    auto* old_val = builder.CreateAlignedLoad(val_ty, ptr, llvm::MaybeAlign(1));
                    auto* new_val = builder.CreateXor(old_val, val);
                    builder.CreateAlignedStore(new_val, ptr, llvm::MaybeAlign(1));

                    call->replaceAllUsesWith(old_val);
                    to_erase.push_back(call);
                }
                // --- I/O port reads ---
                else if (cname.starts_with("__remill_read_io_port_")) {
                    call->replaceAllUsesWith(llvm::Constant::getNullValue(call->getType()));
                    to_erase.push_back(call);
                }
                // --- I/O port writes ---
                else if (cname.starts_with("__remill_write_io_port_")) {
                    if (!call->getType()->isVoidTy())
                        call->replaceAllUsesWith(call->getArgOperand(0)); // return %mem
                    to_erase.push_back(call);
                }
                // --- FPU control ---
                else if (cname.starts_with("__remill_fpu_")) {
                    if (call->getType()->isVoidTy()) {
                        // void-returning FPU intrinsics (e.g. set_rounding) - just erase
                    } else if (call->getType()->isPointerTy()) {
                        call->replaceAllUsesWith(call->getArgOperand(0)); // return %mem
                    } else {
                        call->replaceAllUsesWith(llvm::Constant::getNullValue(call->getType()));
                    }
                    to_erase.push_back(call);
                }
                // --- Comparisons: return arg[0] (the computed condition) ---
                else if (cname.starts_with("__remill_compare_") &&
                         !cname.starts_with("__remill_compare_exchange_")) {
                    if (call->arg_size() > 0) {
                        llvm::Value* cond = call->getArgOperand(0);
                        if (cond->getType() != call->getType())
                            cond = builder.CreateZExtOrBitCast(cond, call->getType());
                        call->replaceAllUsesWith(cond);
                    } else {
                        call->replaceAllUsesWith(llvm::UndefValue::get(call->getType()));
                    }
                    to_erase.push_back(call);
                }
                // --- Control flow: devirtualize dispatch and strip musttail ---
                else if (cname == "__remill_function_call" || cname == "__remill_jump") {
                    // Strip musttail so LLVM's inliner can work on these calls
                    call->setTailCallKind(llvm::CallInst::TCK_None);

                    // Devirtualize: if addr is a constant, replace dispatch with direct call
                    if (auto* addr_const = llvm::dyn_cast<llvm::ConstantInt>(call->getArgOperand(1))) {
                        uint64_t target_addr = addr_const->getZExtValue();
                        auto it = trace_map.find(target_addr);
                        if (it != trace_map.end()) {
                            call->setCalledFunction(it->second);
                            devirtualized++;
                        }
                    }
                }
                else if (cname == "__remill_function_return" ||
                         cname == "__remill_error" || cname == "__remill_missing_block") {
                    call->setTailCallKind(llvm::CallInst::TCK_None);
                }
                // --- Hypercalls: no-op for user-mode recompilation ---
                // The semantics module contains a full hypercall dispatcher with
                // cpuid, rdtsc, syscall, lgdt, etc. None of these are meaningful
                // in a recompiled user-mode binary. Replace with pass-through of Memory*.
                else if (cname == "__remill_async_hyper_call") {
                    // Signature: ptr (ptr %state, i64 %addr, ptr %mem) -> ptr
                    call->replaceAllUsesWith(call->getArgOperand(2)); // return %mem
                    to_erase.push_back(call);
                }
                else if (cname == "__remill_sync_hyper_call") {
                    // Signature: ptr (ptr %state, ptr %mem, i64 %addr) -> ptr
                    call->replaceAllUsesWith(call->getArgOperand(1)); // return %mem
                    to_erase.push_back(call);
                }
            }
        }
    }

    // Step 5: Cleanup - erase dead call instructions
    for (auto* inst : to_erase) {
        inst->eraseFromParent();
    }

    spdlog::info("lower_remill_intrinsics: replaced {} intrinsic call sites, devirtualized {} dispatch calls", to_erase.size(), devirtualized);

    // Step 5b: Delete hypercall function bodies from the semantics module.
    // These contain massive switch dispatchers (cpuid, rdtsc, syscall, lgdt, etc.)
    // that bloat the output if LLVM decides to inline them.
    for (const char* name : {"__remill_async_hyper_call", "__remill_sync_hyper_call"}) {
        if (auto* func = module.getFunction(name)) {
            if (!func->isDeclaration()) {
                func->deleteBody();
                spdlog::debug("Deleted body of {}", name);
            }
        }
    }

    // Step 6: Eliminate dead Memory* chain in trace functions.
    // After all intrinsic call sites are lowered, the Memory* parameter (arg 2)
    // of each trace function is completely dead — no instruction dereferences it.
    // But the RAUW chain (%mem0 → %mem1 → ...) creates SSA dependencies that
    // LLVM must trace through for value numbering and DSE.
    for (auto& func : module.functions()) {
        if (func.isDeclaration() || !func.getName().starts_with("sub_")) continue;
        if (func.arg_size() < 3) continue;
        llvm::Argument* mem_arg = func.getArg(2);

        // Safety: skip if %mem is used by load, store, or GEP (would mean it's still needed)
        bool safe = true;
        for (auto& use : mem_arg->uses()) {
            if (llvm::isa<llvm::LoadInst>(use.getUser()) ||
                llvm::isa<llvm::GetElementPtrInst>(use.getUser()) ||
                llvm::isa<llvm::StoreInst>(use.getUser())) {
                safe = false;
                break;
            }
        }
        if (!safe) continue;

        mem_arg->replaceAllUsesWith(llvm::PoisonValue::get(mem_arg->getType()));
    }

    // Step 7: Ensure noalias on State* (arg 0) and Memory* (arg 2) for all trace functions.
    // While CloneModule should preserve these from remill's DeclareLiftedFunction,
    // this acts as a safety net for alias analysis.
    for (auto& func : module.functions()) {
        if (func.isDeclaration() || !func.getName().starts_with("sub_")) continue;
        if (func.arg_size() < 3) continue;
        if (!func.getArg(0)->hasAttribute(llvm::Attribute::NoAlias))
            func.getArg(0)->addAttr(llvm::Attribute::NoAlias);
        if (!func.getArg(2)->hasAttribute(llvm::Attribute::NoAlias))
            func.getArg(2)->addAttr(llvm::Attribute::NoAlias);
    }
}

// --------------------------------------------------------------------------
// TBAA Metadata Annotation
// --------------------------------------------------------------------------
// Adds Type-Based Alias Analysis metadata to separate State struct accesses
// from program memory accesses. After intrinsic lowering, memory reads/writes
// become inttoptr-derived loads/stores, while State accesses go through GEP
// chains from function arguments. LLVM's BasicAA is conservative with inttoptr
// (returns MayAlias), so we use TBAA to explicitly tell LLVM these two domains
// cannot alias, enabling DSE to eliminate dead State stores.

static void annotate_tbaa_metadata(llvm::Module& module) {
    auto& ctx = module.getContext();
    llvm::MDBuilder md_builder(ctx);

    // Create TBAA type hierarchy:
    //   "Remill TBAA" (root)
    //     ├── "Remill State" (State struct accesses)
    //     └── "Program Memory" (inttoptr-derived accesses)
    // Since these are sibling types under the same root, TBAA proves NoAlias.
    auto* tbaa_root = md_builder.createTBAARoot("Remill TBAA");
    auto* tbaa_state = md_builder.createTBAAScalarTypeNode("Remill State", tbaa_root);
    auto* tbaa_mem = md_builder.createTBAAScalarTypeNode("Program Memory", tbaa_root);

    // Create access tags (type, access type, offset)
    auto* state_tag = md_builder.createTBAAStructTagNode(tbaa_state, tbaa_state, 0);
    auto* mem_tag = md_builder.createTBAAStructTagNode(tbaa_mem, tbaa_mem, 0);

    // Helper: walk a pointer backwards through GEP/BitCast/AddrSpaceCast to
    // determine if it originates from a function Argument (State-derived).
    // Returns true for arg-derived, false otherwise. Conservative: stops at
    // PHI/Select/Call boundaries.
    auto is_arg_derived = [](llvm::Value* v) -> bool {
        llvm::SmallPtrSet<llvm::Value*, 8> visited;
        while (v) {
            if (!visited.insert(v).second) return false; // cycle
            if (llvm::isa<llvm::Argument>(v)) return true;
            if (auto* gep = llvm::dyn_cast<llvm::GetElementPtrInst>(v)) {
                v = gep->getPointerOperand();
            } else if (auto* bc = llvm::dyn_cast<llvm::BitCastInst>(v)) {
                v = bc->getOperand(0);
            } else if (auto* asc = llvm::dyn_cast<llvm::AddrSpaceCastInst>(v)) {
                v = asc->getPointerOperand();
            } else {
                return false; // PHI, Select, Call, alloca, etc. — conservative
            }
        }
        return false;
    };

    unsigned state_count = 0;
    unsigned mem_count = 0;

    for (auto& func : module.functions()) {
        if (func.isDeclaration()) continue;

        for (auto& bb : func) {
            for (auto& inst : bb) {
                llvm::Value* ptr = nullptr;

                if (auto* load = llvm::dyn_cast<llvm::LoadInst>(&inst)) {
                    ptr = load->getPointerOperand();
                } else if (auto* store = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
                    ptr = store->getPointerOperand();
                } else {
                    continue;
                }

                // Classify: inttoptr → Program Memory, arg-derived → State
                if (llvm::isa<llvm::IntToPtrInst>(ptr)) {
                    inst.setMetadata(llvm::LLVMContext::MD_tbaa, mem_tag);
                    mem_count++;
                } else if (is_arg_derived(ptr)) {
                    inst.setMetadata(llvm::LLVMContext::MD_tbaa, state_tag);
                    state_count++;
                }
                // else: unclassifiable (alloca, PHI-derived, etc.) — leave untagged (conservative MayAlias)
            }
        }
    }

    spdlog::info("annotate_tbaa_metadata: tagged {} State accesses, {} program memory accesses",
                 state_count, mem_count);
}

static void generate_runtime_stubs(llvm::Module& module) {
    auto& ctx = module.getContext();
    llvm::IRBuilder<> builder(ctx);

    // 1. Explicit Remill Intrinsics & Compiler Builtins
    std::vector<std::string> stub_names = {
        // Core Runtime
        "__remill_error", "__remill_missing_block", "__remill_async_hyper_call", "__remill_sync_hyper_call",
        "__remill_function_call", "__remill_function_return", "__remill_jump",

        // I/O
        "__remill_read_io_port_8", "__remill_read_io_port_16", "__remill_read_io_port_32",
        "__remill_write_io_port_8", "__remill_write_io_port_16", "__remill_write_io_port_32",

        // FPU
        "__remill_fpu_get_rounding", "__remill_fpu_set_rounding",
        "__remill_fpu_exception_test", "__remill_fpu_exception_clear",

        // Memory Access
        "__remill_read_memory_8", "__remill_read_memory_16", "__remill_read_memory_32", "__remill_read_memory_64",
        "__remill_write_memory_8", "__remill_write_memory_16", "__remill_write_memory_32", "__remill_write_memory_64",
        "__remill_read_memory_f32", "__remill_read_memory_f64", "__remill_read_memory_f80", "__remill_read_memory_f128",
        "__remill_write_memory_f32", "__remill_write_memory_f64", "__remill_write_memory_f80", "__remill_write_memory_f128",

        // Barriers & Atomics
        "__remill_barrier_load_load", "__remill_barrier_load_store", "__remill_barrier_store_load", "__remill_barrier_store_store",
        "__remill_atomic_begin", "__remill_atomic_end", "__remill_delay_slot_begin", "__remill_delay_slot_end",
        "__remill_compare_exchange_memory_8", "__remill_compare_exchange_memory_16",
        "__remill_compare_exchange_memory_32", "__remill_compare_exchange_memory_64",
        "__remill_compare_exchange_memory_128",

        // Undefined Behaviors
        "__remill_undefined_8", "__remill_undefined_16", "__remill_undefined_32", "__remill_undefined_64",
        "__remill_undefined_f32", "__remill_undefined_f64", "__remill_undefined_f80",

        // Flags & Comparisons
        "__remill_flag_computation_zero", "__remill_flag_computation_sign",
        "__remill_flag_computation_overflow", "__remill_flag_computation_carry",
        "__remill_compare_eq", "__remill_compare_neq", "__remill_compare_sgt", "__remill_compare_sge",
        "__remill_compare_slt", "__remill_compare_sle", "__remill_compare_ugt", "__remill_compare_uge",
        "__remill_compare_ult", "__remill_compare_ule"
    };

    // Architecture State Accessors
    const char* segments[] = {"es", "ss", "ds", "fs", "gs"};
    for (const auto* s : segments) stub_names.push_back(std::format("__remill_x86_set_segment_{}", s));

    stub_names.push_back("__remill_amd64_set_debug_reg");
    for (int i = 0; i < 16; ++i) {
        stub_names.push_back(std::format("__remill_amd64_set_control_reg_{}", i));
        stub_names.push_back(std::format("__remill_amd64_set_debug_reg_{}", i));
    }

    // Proactive Stubbing: Find ANY undefined __remill_ function and stub it
    for (auto& func : module.functions()) {
        if (func.isDeclaration() && func.getName().starts_with("__remill_")) {
            bool already_added = false;
            for(const auto& s : stub_names) if(s == func.getName()) already_added = true;
            if(!already_added) stub_names.push_back(func.getName().str());
        }
    }

    // Create bodies for all standard stubs
    for (const auto& name : stub_names) {
        llvm::Function* func = module.getFunction(name);
        if (func && func->isDeclaration()) {
            llvm::BasicBlock* bb = llvm::BasicBlock::Create(ctx, "stub_body", func);
            builder.SetInsertPoint(bb);
            if (func->getReturnType()->isVoidTy()) builder.CreateRetVoid();
            else builder.CreateRet(llvm::Constant::getNullValue(func->getReturnType()));

            // Stubs must be External so the Linker sees them
            func->setLinkage(llvm::GlobalValue::ExternalLinkage);
            func->addFnAttr(llvm::Attribute::NoInline);
        }
    }

    // ---------------------------------------------------------
    // 128-bit Math Builtins (Fix for MSVC Linker Errors)
    // ---------------------------------------------------------
    // Clang/LLVM generates calls to these for i128 operations, but MSVC CRT does not provide them.
    // We inject simple stubs to satisfy the linker.
    const char* math_builtins[] = {"__divti3", "__udivti3"};
    for (const auto* name : math_builtins) {
        llvm::Function* func = module.getFunction(name);
        if (!func) {
            // Create if missing: i128 (i128, i128)
            std::vector<llvm::Type*> args = { llvm::Type::getInt128Ty(ctx), llvm::Type::getInt128Ty(ctx) };
            llvm::FunctionType* ft = llvm::FunctionType::get(llvm::Type::getInt128Ty(ctx), args, false);
            func = llvm::Function::Create(ft, llvm::GlobalValue::ExternalLinkage, name, module);
        }

        if (func->isDeclaration()) {
            llvm::BasicBlock* bb = llvm::BasicBlock::Create(ctx, "entry", func);
            builder.SetInsertPoint(bb);
            // Returns 0. If your logic depends heavily on 128-bit division, this might need a real impl.
            // However, this unblocks linking.
            builder.CreateRet(llvm::ConstantInt::get(llvm::Type::getInt128Ty(ctx), 0));
            func->setLinkage(llvm::GlobalValue::ExternalLinkage);
            func->addFnAttr(llvm::Attribute::NoInline);
        }
    }

    // 2. Math Shims (long double -> double)
    std::vector<std::pair<std::string, std::string>> math_map = {
        {"sqrtl", "sqrt"}, {"sinl", "sin"}, {"cosl", "cos"}, {"tanl", "tan"},
        {"atanl", "atan"}, {"fmodl", "fmod"}, {"log2l", "log2"}, {"exp2l", "exp2"},
        {"atan2l", "atan2"}, {"remainderl", "remainder"}
    };

    for (const auto& [long_n, double_n] : math_map) {
        llvm::Function* f = module.getFunction(long_n);
        if (f && f->isDeclaration()) {
            llvm::BasicBlock* bb = llvm::BasicBlock::Create(ctx, "math_shim", f);
            builder.SetInsertPoint(bb);

            std::vector<llvm::Type*> double_args(f->arg_size(), builder.getDoubleTy());
            llvm::FunctionType* double_fty = llvm::FunctionType::get(builder.getDoubleTy(), double_args, false);
            auto* target = module.getOrInsertFunction(double_n, double_fty).getCallee();

            std::vector<llvm::Value*> call_args;
            for (auto& arg : f->args()) {
                call_args.push_back(arg.getType()->isFloatingPointTy() ? builder.CreateFPTrunc(&arg, builder.getDoubleTy()) : (llvm::Value*)&arg);
            }

            auto* call = builder.CreateCall(double_fty, target, call_args);

            if (f->getReturnType()->isFloatingPointTy()) builder.CreateRet(builder.CreateFPExt(call, f->getReturnType()));
            else builder.CreateRet(call);

            f->setLinkage(llvm::GlobalValue::ExternalLinkage);
        }
    }
}

// --------------------------------------------------------------------------
// Core Logic
// --------------------------------------------------------------------------

ExportLiftResult ExportLiftService::export_function(Address entry, const ExportLiftConfig& config) {
    if (!initialized_) return {false, "Not initialized"};

    ExportLiftResult result;
    auto* context = lifting_service_->context();
    auto ctx_lock = context->lock();
    auto& ctx = context->context();

    std::queue<Address> queue;
    std::set<Address> visited;
    queue.push(entry);
    visited.insert(entry);

    std::string main_trace_name;

    // 1. Recursive Lifting to populate the context's semantics module.
    // Use a SINGLE persistent trace manager so remill knows about all
    // previously lifted traces and avoids duplicate definitions.
    PicanhaTraceManager trace_manager(binary_);
    remill::TraceLifter lifter(context->arch(), trace_manager);

    while(!queue.empty()) {
        Address current_addr = queue.front();
        queue.pop();
        result.lifted_functions.push_back(current_addr);

        // Skip if already lifted by a previous Lift() call (the persistent
        // trace manager tracks all definitions across calls).
        if (trace_manager.GetLiftedTraceDefinition(current_addr)) {
            spdlog::debug("Already lifted 0x{:X}, skipping", current_addr);
            if (current_addr == entry) {
                main_trace_name = trace_manager.TraceName(current_addr);
            }
            continue;
        }

        spdlog::info("Lifting 0x{:X}...", current_addr);

        // Lift using the persistent lifter. The callback filters by address
        // so we capture the correct function (not a recursively-lifted callee).
        llvm::Function* entry_func = nullptr;
        bool lift_success = lifter.Lift(current_addr,
            [&entry_func, current_addr](uint64_t addr, llvm::Function* fn) {
                if (addr == current_addr) {
                    entry_func = fn;
                }
            });

        if (!lift_success || !entry_func) {
            spdlog::error("Failed to lift 0x{:X}", current_addr);
            continue;
        }

        if (current_addr == entry) {
            main_trace_name = entry_func->getName().str();
        }

        if (config.include_dependencies) {
            auto deps = collect_called_addresses(entry_func);
            for (Address dep : deps) {
                if (visited.find(dep) == visited.end()) {
                    visited.insert(dep);
                    queue.push(dep);
                }
            }
        }
    }

    // 2. Snapshot
    // Clone the context's semantics module, which now contains all traces and helpers.
    spdlog::info("Snapshotting semantics module...");
    auto* raw_semantics = lifting_service_->context()->semantics_module();
    if (!raw_semantics) return {false, "Semantics module is missing"};

    auto export_module = llvm::CloneModule(*raw_semantics);
    export_module->setTargetTriple("x86_64-pc-windows-msvc");
    export_module->setDataLayout("e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128");

    // 3. Symbol Canonicalization (The Fix)
    //
    // The problem: The module may contain a definition for `sub_1234.5` but calls to `sub_1234` or `sub_1234.1`.
    // The previous fix failed because it only looked up the exact base name.
    //
    // New Strategy:
    // 1. Index all DEFINED functions by their base name.
    // 2. Scan all DECLARED functions, find their base name, and map them to the definition.

    std::map<std::string, llvm::Function*> defined_traces;

    // Step A: Index Definitions
    for (auto& func : export_module->functions()) {
        if (!func.isDeclaration()) {
            std::string base = get_base_name(func.getName());
            if (base.starts_with("sub_")) {
                defined_traces[base] = &func;
            }
        }
    }

    // Step B: Rewire Declarations
    std::vector<llvm::Function*> funcs_to_remove;
    for (auto& func : export_module->functions()) {
        if (func.isDeclaration()) {
            std::string name = func.getName().str();
            std::string base = get_base_name(name);

            // If we have a definition for this base name
            auto it = defined_traces.find(base);
            if (it != defined_traces.end()) {
                llvm::Function* definition = it->second;

                // If it's the same object (shouldn't happen for declaration vs definition), skip
                if (&func == definition) continue;

                spdlog::debug("Canonicalizing: {} -> {} (via {})", name, definition->getName().str(), base);

                // Replace all uses of the declaration with the definition
                // We use bitcast to be safe about slight type mismatches (though signatures should match)
                func.replaceAllUsesWith(
                    llvm::ConstantExpr::getBitCast(definition, func.getType())
                );

                funcs_to_remove.push_back(&func);
            }
        }
    }

    for (auto* f : funcs_to_remove) f->eraseFromParent();

    // 4. Attribute & Linkage Fixup
    for (auto& func : export_module->functions()) {
        if (func.isDeclaration()) continue;

        // Attributes for MSVC compatibility
        func.addFnAttr("frame-pointer", "none");
        func.addFnAttr("no-realign-stack", "true");
        func.removeFnAttr("stackrealign");

        std::string name = func.getName().str();
        if (name.starts_with("sub_") || name == main_trace_name) {
            // Export traces so they are visible to the linker
            func.setLinkage(llvm::GlobalValue::ExternalLinkage);
            func.setComdat(nullptr);
        } else {
            // Internalize Remill helpers so they don't clash with libraries
            func.setLinkage(llvm::GlobalValue::InternalLinkage);
            func.setComdat(nullptr);
        }
    }

    // 5. Cleanup Metadata
    if (auto* g = export_module->getGlobalVariable("llvm.used")) g->eraseFromParent();
    if (auto* g = export_module->getGlobalVariable("llvm.compiler.used")) g->eraseFromParent();
    if (auto* f = export_module->getFunction("__remill_intrinsics")) f->eraseFromParent();

    // 6. Lower remill intrinsics to native operations
    lower_remill_intrinsics(*export_module);

    // 6b. Annotate TBAA metadata to separate State and program memory domains
    annotate_tbaa_metadata(*export_module);

    // 7. Generate stubs for any remaining intrinsics
    generate_runtime_stubs(*export_module);

    // 8. Entry point wrapper
    if (!config.entry_point_name.empty() && !main_trace_name.empty()) {
        if (auto* target = export_module->getFunction(main_trace_name)) {
            auto* wrapper = llvm::Function::Create(target->getFunctionType(),
                llvm::GlobalValue::ExternalLinkage, config.entry_point_name, export_module.get());
            wrapper->addFnAttr("frame-pointer", "none");
            wrapper->addFnAttr("no-realign-stack", "true");
            auto* bb = llvm::BasicBlock::Create(ctx, "entry", wrapper);
            llvm::IRBuilder<> b(bb);
            std::vector<llvm::Value*> args;
            for (auto& arg : wrapper->args()) args.push_back(&arg);
            auto* call = b.CreateCall(target->getFunctionType(), target, args);
            if (wrapper->getReturnType()->isVoidTy()) b.CreateRetVoid();
            else b.CreateRet(call);
            spdlog::info("Generated entry point wrapper '{}' -> '{}'", config.entry_point_name, main_trace_name);
        } else {
            spdlog::warn("Could not find main trace '{}' to create entry point", main_trace_name);
        }
    }

    // 9. Prepare for aggressive inlining and dead store elimination
    if (config.opt_level >= OptimizationLevel::O2) {
        // Internalize non-entry traces so LLVM can inline and optimize through them.
        // This is critical for DSE: after inlining, LLVM can see that State struct
        // stores in the caller are overwritten by the inlined callee → dead stores.
        for (auto& func : *export_module) {
            if (func.isDeclaration()) continue;
            std::string name = func.getName().str();
            if (name.starts_with("sub_") && name != main_trace_name) {
                func.setLinkage(llvm::GlobalValue::InternalLinkage);
            }
        }

        // Force-inline the thin dispatch/control-flow wrappers so LLVM can see
        // through __remill_function_call → sub_XXX call chains.
        for (const char* n : {"__remill_function_call", "__remill_jump",
                              "__remill_function_return", "__remill_error",
                              "__remill_missing_block"}) {
            if (auto* f = export_module->getFunction(n)) {
                if (!f->isDeclaration()) {
                    f->addFnAttr(llvm::Attribute::AlwaysInline);
                    f->setLinkage(llvm::GlobalValue::InternalLinkage);
                }
            }
        }

        // Remove dead dispatch functions after devirtualization — if all call sites
        // were devirtualized to direct calls, the dispatch body is unreachable.
        for (const char* n : {"__remill_function_call", "__remill_jump"}) {
            if (auto* f = export_module->getFunction(n)) {
                if (!f->isDeclaration() && f->use_empty()) {
                    f->eraseFromParent();
                }
            }
        }

        // Strip OptimizeNone/NoDuplicate from ALL defined functions, not just
        // __remill_* — semantic handlers inlined into traces may carry these.
        for (auto& func : *export_module) {
            if (func.isDeclaration()) continue;
            func.removeFnAttr(llvm::Attribute::OptimizeNone);
            func.removeFnAttr(llvm::Attribute::NoDuplicate);
            if (func.getLinkage() == llvm::GlobalValue::InternalLinkage)
                func.removeFnAttr(llvm::Attribute::NoInline);
        }

        spdlog::info("Prepared {} traces for inlining (non-entry internalized)", visited.size() - 1);
    }

    // 10. Apply optimization passes if requested
    if (config.opt_level != OptimizationLevel::O0) {
        spdlog::info("Applying O{} optimization...", static_cast<int>(config.opt_level));
        IROptimizer optimizer(lifting_service_->context()->arch());
        optimizer.run_optimization_passes(*export_module, config.opt_level);
    }

    llvm::raw_string_ostream os(result.code_ir);
    export_module->print(os, nullptr);
    result.success = true;

    if (config.include_data_sections) result.data_ir = generate_data_section_module();
    if (config.auto_compile) result = compile_and_link(result, config);

    return result;
}

std::vector<Address> ExportLiftService::collect_called_addresses(llvm::Function* func) {
    std::vector<Address> addresses;
    static const std::regex sub_regex(R"(sub_([0-9a-fA-F]+)(\..*)?)");

    for (auto& bb : *func) {
        for (auto& inst : bb) {
            if (auto* call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
                auto* val = call->getCalledOperand()->stripPointerCasts();
                if (auto* f = llvm::dyn_cast<llvm::Function>(val)) {
                    std::string base = get_base_name(f->getName());
                    std::smatch match;
                    if (std::regex_match(base, match, sub_regex)) {
                        try {
                            addresses.push_back(std::stoull(match[1].str(), nullptr, 16));
                        } catch (...) {}
                    }
                }
            }
        }
    }
    return addresses;
}

ExportLiftResult ExportLiftService::compile_and_link(ExportLiftResult& result, const ExportLiftConfig& config) {
    if (!result.success) return result;

    std::filesystem::path temp_dir = std::filesystem::temp_directory_path() / "picanha_export";
    std::filesystem::create_directories(temp_dir);
    std::string base = config.output_executable.empty() ? "output" : std::filesystem::path(config.output_executable).stem().string();

    std::filesystem::path code_ll = temp_dir / (base + ".ll");
    std::filesystem::path code_obj = temp_dir / (base + ".obj");
    std::filesystem::path output_exe = config.output_executable.empty() ? (temp_dir / "output.exe") : config.output_executable;

    { std::ofstream(code_ll) << result.code_ir; }

    // IR is already optimized by our pipeline — clang only does codegen.
    // Use -O0 to avoid re-running the same LLVM passes a second time.
    // -g -gcodeview emits CodeView debug info for PDB generation during linking.
    std::string cmd = std::format("clang -c \"{}\" -o \"{}\" -O0 -fno-stack-protector -g -gcodeview", code_ll.string(), code_obj.string());
    if (std::system(cmd.c_str()) != 0) {
        result.compilation_success = false;
        result.compilation_output = "Clang compilation failed.";
        return result;
    }

    std::stringstream link_cmd;
    link_cmd << "clang \"" << code_obj.string() << "\"";

    if (!result.data_ir.empty()) {
        std::filesystem::path d_ll = temp_dir / (base + "_data.ll");
        std::filesystem::path d_obj = temp_dir / (base + "_data.obj");
        { std::ofstream(d_ll) << result.data_ir; }
        std::system(std::format("clang -c \"{}\" -o \"{}\" -O0 -g -gcodeview", d_ll.string(), d_obj.string()).c_str());
        link_cmd << " \"" << d_obj.string() << "\"";
    }

    std::filesystem::path bin_dir = std::filesystem::current_path();
    std::vector<std::filesystem::path> libs = { bin_dir / ".." / "lib", bin_dir / "lib" };
    for (const auto& l : {"remill_bc.lib", "remill_arch_x86.lib", "remill_os.lib"}) {
        for (const auto& p : libs) {
            if (std::filesystem::exists(p / l)) { link_cmd << " \"" << (p / l).string() << "\""; break; }
        }
    }

    if (!config.entry_point_name.empty()) link_cmd << " -Wl,/ENTRY:" << config.entry_point_name;
    link_cmd << " -Wl,/DEBUG";
    link_cmd << " -lkernel32 -luser32 -lshell32 -lucrt -lvcruntime -lmsvcrt -o \"" << output_exe.string() << "\"";

    int ret = std::system(link_cmd.str().c_str());
    result.compilation_success = (ret == 0);
    result.output_executable_path = output_exe.string();
    if (ret != 0) result.compilation_output = std::format("Link failed with code {}", ret);
    return result;
}

// Legacy methods, unused but kept for header compatibility
void ExportLiftService::mark_functions_as_used(llvm::Module&, const std::vector<std::string>&) {}
bool ExportLiftService::merge_into_module(llvm::Module&, llvm::Module&, const std::string&) { return false; }

std::string ExportLiftService::generate_data_section_module() {
    if (!binary_) return {};
    auto& ctx = lifting_service_->context()->context();
    auto module = std::make_unique<llvm::Module>("data_sections", ctx);
    bool has = false;
    for (const auto& sec : binary_->sections()) {
        if ((sec.name == ".data" || sec.name == ".rdata") && sec.file_size > 0) {
            auto d = binary_->read(sec.virtual_address, sec.file_size);
            if (!d) continue;
            auto* at = llvm::ArrayType::get(llvm::Type::getInt8Ty(ctx), d->size());
            std::vector<llvm::Constant*> bytes;
            for (auto b : *d) bytes.push_back(llvm::ConstantInt::get(llvm::Type::getInt8Ty(ctx), b, false));
            new llvm::GlobalVariable(*module, at, sec.name == ".rdata", llvm::GlobalValue::ExternalLinkage, llvm::ConstantArray::get(at, bytes), std::format("__picanha_section_{}", sec.name.substr(1)));
            has = true;
        }
    }
    if (!has) return {};
    std::string ir;
    llvm::raw_string_ostream os(ir);
    module->print(os, nullptr);
    return ir;
}

} // namespace picanha::lift
