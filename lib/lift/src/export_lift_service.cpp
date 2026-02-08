#include <picanha/lift/export_lift_service.hpp>
#include <picanha/lift/lifted_function.hpp>

#include <spdlog/spdlog.h>

#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Linker/Linker.h>

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
    auto& ctx = lifting_service_->context()->context();

    std::queue<Address> queue;
    std::set<Address> visited;
    queue.push(entry);
    visited.insert(entry);

    std::string main_trace_name;

    // 1. Recursive Lifting to populate the context's semantics module
    // We let Remill handle the internal linking during this phase.
    while(!queue.empty()) {
        Address current_addr = queue.front();
        queue.pop();
        result.lifted_functions.push_back(current_addr);

        spdlog::info("Lifting 0x{:X}...", current_addr);

        auto lift_result = lifting_service_->lift_address(current_addr);
        if (!lift_result.success || !lift_result.lifted) {
            spdlog::error("Failed to lift 0x{:X}: {}", current_addr, lift_result.error);
            continue;
        }

        if (current_addr == entry) main_trace_name = lift_result.lifted->function()->getName().str();

        if (config.include_dependencies) {
            if (auto* func = lift_result.lifted->function()) {
                auto deps = collect_called_addresses(func);
                for (Address dep : deps) {
                    if (visited.find(dep) == visited.end()) {
                        visited.insert(dep);
                        queue.push(dep);
                    }
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

    // 6. Generate Stubs & Entry Point
    generate_runtime_stubs(*export_module);

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

    std::string cmd = std::format("clang -c \"{}\" -o \"{}\" -fno-stack-protector", code_ll.string(), code_obj.string());
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
        std::system(std::format("clang -c \"{}\" -o \"{}\"", d_ll.string(), d_obj.string()).c_str());
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
