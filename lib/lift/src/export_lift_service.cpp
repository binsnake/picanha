#include <picanha/lift/export_lift_service.hpp>
#include <picanha/lift/lifted_function.hpp>

#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/IPO/GlobalDCE.h>
#include <llvm/Linker/Linker.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Bitcode/BitcodeWriter.h>

#include <remill/BC/Util.h>

#include <format>
#include <sstream>
#include <filesystem>
#include <cstdlib>

namespace picanha::lift {

ExportLiftService::ExportLiftService(std::shared_ptr<loader::Binary> binary)
    : binary_(std::move(binary))
    , lifting_service_(std::make_unique<LiftingService>(binary_))
{
}

ExportLiftService::~ExportLiftService() = default;

bool ExportLiftService::initialize() {
    if (initialized_) {
        return true;
    }

    if (!lifting_service_->initialize()) {
        error_ = "Failed to initialize lifting service: " + lifting_service_->error_message();
        return false;
    }

    initialized_ = true;
    return true;
}

ExportLiftResult ExportLiftService::export_function(Address entry, const ExportLiftConfig& config) {
    if (!initialized_) {
        return ExportLiftResult{false, "Export lift service not initialized", {}, {}, {}, {}};
    }

    ExportLiftResult result;
    std::unordered_set<Address> visited;
    
    // Lift main function and all dependencies
    auto& ctx = lifting_service_->context()->context();
    auto merged_module = std::make_unique<llvm::Module>("exported_module", ctx);
    merged_module->setTargetTriple("x86_64-pc-windows-msvc");
    merged_module->setDataLayout("e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128");
    
    std::string main_func_name;
    std::vector<std::string> all_lifted_functions;
    
    // Recursively lift and merge
    std::function<bool(Address, std::size_t)> lift_and_merge = [&](Address addr, std::size_t depth) -> bool {
        if (depth > config.max_dependency_depth || visited.count(addr)) {
            return true;
        }
        visited.insert(addr);
        result.lifted_functions.push_back(addr);
        
        // Lift the function
        auto lift_result = lifting_service_->lift_address(addr);
        if (!lift_result.success || !lift_result.lifted) {
            result.error_message = std::format("Failed to lift function at 0x{:X}: {}", 
                addr, lift_result.error);
            return false;
        }
        
        // Apply optimization if requested
        if (config.opt_level > OptimizationLevel::O0) {
            lifting_service_->optimize(*lift_result.lifted, config.opt_level);
        }
        
        auto* module = lift_result.lifted->module();
        if (!module) {
            return false;
        }
        
        // Get function name
        std::string func_name = lift_result.lifted->function() ? 
            lift_result.lifted->function()->getName().str() : std::format("sub_{:X}", addr);
        
        if (addr == entry) {
            main_func_name = func_name;
        }
        
        all_lifted_functions.push_back(func_name);
        
        // Merge into main module
        if (!merge_into_module(*merged_module, *module, func_name)) {
            result.error_message = std::format("Failed to merge function at 0x{:X}", addr);
            return false;
        }
        
        // Recursively lift dependencies if requested
        if (config.include_dependencies) {
            auto* func = module->getFunction(func_name);
            if (func) {
                auto deps = collect_called_addresses(func);
                for (Address dep_addr : deps) {
                    if (!lift_and_merge(dep_addr, depth + 1)) {
                        return false;
                    }
                }
            }
        }
        
        return true;
    };
    
    if (!lift_and_merge(entry, 0)) {
        return result;
    }
    
    // Mark all functions as used
    mark_functions_as_used(*merged_module, all_lifted_functions);
    
    // Set external linkage for all functions
    for (auto& func : merged_module->functions()) {
        if (!func.isDeclaration()) {
            func.setLinkage(llvm::GlobalValue::ExternalLinkage);
            func.removeFnAttr(llvm::Attribute::NoInline);
            func.removeFnAttr(llvm::Attribute::OptimizeNone);
        }
    }
    
    // Create entry point alias
    if (!config.entry_point_name.empty() && !main_func_name.empty()) {
        auto* main_func = merged_module->getFunction(main_func_name);
        if (main_func) {
            llvm::GlobalAlias::create(
                main_func->getValueType(),
                0,
                llvm::GlobalValue::ExternalLinkage,
                config.entry_point_name,
                main_func,
                merged_module.get()
            );
        }
    }
    
    // Handle frame pointer conflicts - apply to ALL functions
    // Remill's runtime uses inline assembly that manipulates the frame pointer,
    // which conflicts with clang's frame pointer usage. We must disable frame
    // pointers for ALL functions to avoid this conflict.
    for (auto& func : merged_module->functions()) {
        if (!func.isDeclaration()) {
            func.addFnAttr("frame-pointer", "none");
        }
    }
    
    // Collect unresolved symbols
    for (auto& func : merged_module->functions()) {
        if (func.isDeclaration()) {
            std::string name = func.getName().str();
            // Skip LLVM intrinsics and known external symbols
            if (!name.starts_with("llvm.") && 
                !name.starts_with("__remill_") &&
                name != "memset" && name != "memcpy" && name != "memmove") {
                result.unresolved_symbols.push_back(name);
            }
        }
    }
    
    // Generate IR text
    std::string ir_text;
    llvm::raw_string_ostream os(ir_text);
    merged_module->print(os, nullptr);
    os.flush();
    
    result.code_ir = std::move(ir_text);
    result.success = true;
    
    // Generate data sections
    if (config.include_data_sections) {
        result.data_ir = generate_data_section_module();
        if (!result.data_ir.empty()) {
            result.included_data_sections.push_back(".data");
            result.included_data_sections.push_back(".rdata");
        }
    }
    
    // Auto-compile if requested
    if (config.auto_compile && config.include_dependencies) {
        result = compile_and_link(result, config);
    }
    
    return result;
}

ExportLiftResult ExportLiftService::compile_and_link(ExportLiftResult& result, const ExportLiftConfig& config) {
    if (!result.success) {
        return result;
    }
    
    std::filesystem::path temp_dir = std::filesystem::temp_directory_path() / "picanha_export";
    std::filesystem::create_directories(temp_dir);
    
    std::string base_name = config.output_executable.empty() ? "output" : 
        std::filesystem::path(config.output_executable).stem().string();
    
    std::filesystem::path code_ll = temp_dir / (base_name + ".ll");
    std::filesystem::path code_obj = temp_dir / (base_name + ".obj");
    std::filesystem::path data_obj;
    std::filesystem::path output_exe = config.output_executable.empty() ? 
        (temp_dir / "output.exe") : config.output_executable;
    
    // Write code IR
    {
        std::ofstream out(code_ll);
        out << result.code_ir;
    }
    
    // Compile code with frame pointer disabled
    std::string compile_cmd = std::format("clang -c \"{}\" -o \"{}\" -fomit-frame-pointer -fno-stack-protector", 
        code_ll.string(), code_obj.string());
    int ret = std::system(compile_cmd.c_str());
    if (ret != 0) {
        result.compilation_success = false;
        result.compilation_output = "Failed to compile code module";
        return result;
    }
    
    // Compile data if present
    std::vector<std::string> objects_to_link;
    objects_to_link.push_back(code_obj.string());
    
    if (!result.data_ir.empty()) {
        std::filesystem::path data_ll = temp_dir / (base_name + "_data.ll");
        data_obj = temp_dir / (base_name + "_data.obj");
        
        {
            std::ofstream out(data_ll);
            out << result.data_ir;
        }
        
        std::string data_compile_cmd = std::format("clang -c \"{}\" -o \"{}\"", data_ll.string(), data_obj.string());
        ret = std::system(data_compile_cmd.c_str());
        if (ret != 0) {
            result.compilation_success = false;
            result.compilation_output = "Failed to compile data module";
            return result;
        }
        
        objects_to_link.push_back(data_obj.string());
    }
    
    // Link
    std::string link_cmd = "clang";
    for (const auto& obj : objects_to_link) {
        link_cmd += std::format(" \"{}\"", obj);
    }
    
    // Add entry point
    if (!config.entry_point_name.empty()) {
        link_cmd += std::format(" -Wl,/ENTRY:{}", config.entry_point_name);
    }
    
    // Add remill library if provided
    if (!config.remill_lib_path.empty()) {
        std::filesystem::path remill_path(config.remill_lib_path);
        if (remill_path.extension() == ".bc") {
            // Bitcode files can't be easily compiled due to inline asm conflicts
            result.compilation_success = false;
            result.compilation_output = std::format(
                "Cannot use bitcode file '{}'. Please use pre-compiled .lib files instead.\n"
                "Available remill libraries in build/qt-llvm-release/lib/:\n"
                "  - remill_bc.lib (runtime library)\n"
                "  - remill_arch_x86.lib (x86 architecture support)\n"
                "  - remill_os.lib (OS support)", 
                config.remill_lib_path);
            return result;
        } else {
            link_cmd += std::format(" \"{}\"", config.remill_lib_path);
        }
    }
    
    // Add required system libraries and math library
    link_cmd += " -lkernel32 -luser32 -lshell32 -lm";
    
    link_cmd += std::format(" -o \"{}\"", output_exe.string());
    
    ret = std::system(link_cmd.c_str());
    if (ret != 0) {
        result.compilation_success = false;
        result.compilation_output = std::format("Link failed. Command: {}", link_cmd);
        return result;
    }
    
    result.compilation_success = true;
    result.output_executable_path = output_exe.string();
    
    return result;
}

std::vector<Address> ExportLiftService::collect_called_addresses(llvm::Function* func) {
    std::vector<Address> addresses;
    
    if (!func) {
        return addresses;
    }

    for (auto& bb : *func) {
        for (auto& inst : bb) {
            if (auto* call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
                if (auto* callee = call->getCalledFunction()) {
                    std::string name = callee->getName().str();
                    if (name.starts_with("sub_")) {
                        try {
                            std::string addr_str = name.substr(4);
                            Address addr = std::stoull(addr_str, nullptr, 16);
                            addresses.push_back(addr);
                        } catch (...) {
                            // Ignore
                        }
                    }
                }
            }
        }
    }

    return addresses;
}

void ExportLiftService::mark_functions_as_used(llvm::Module& module, const std::vector<std::string>& func_names) {
    llvm::LLVMContext& ctx = module.getContext();
    
    llvm::GlobalVariable* used_var = module.getGlobalVariable("llvm.used");
    std::vector<llvm::Constant*> used_values;
    
    if (used_var && used_var->hasInitializer()) {
        if (auto* existing = llvm::dyn_cast<llvm::ConstantArray>(used_var->getInitializer())) {
            for (unsigned i = 0; i < existing->getNumOperands(); ++i) {
                used_values.push_back(existing->getOperand(i));
            }
        }
        used_var->eraseFromParent();
    }
    
    for (const auto& name : func_names) {
        llvm::Function* func = module.getFunction(name);
        if (func) {
            llvm::Type* i8_ptr = llvm::PointerType::getUnqual(ctx);
            auto* bitcast = llvm::ConstantExpr::getBitCast(func, i8_ptr);
            used_values.push_back(bitcast);
        }
    }
    
    if (used_values.empty()) {
        return;
    }
    
    llvm::ArrayType* array_type = llvm::ArrayType::get(
        llvm::PointerType::getUnqual(ctx),
        used_values.size()
    );
    
    llvm::Constant* initializer = llvm::ConstantArray::get(array_type, used_values);
    
    used_var = new llvm::GlobalVariable(
        module,
        array_type,
        false,
        llvm::GlobalValue::AppendingLinkage,
        initializer,
        "llvm.used"
    );
    
    used_var->setSection("llvm.metadata");
}

std::string ExportLiftService::generate_data_section_module() {
    if (!binary_) {
        return {};
    }

    auto& ctx = lifting_service_->context()->context();
    auto module = std::make_unique<llvm::Module>("data_sections", ctx);
    
    bool has_data = false;
    
    for (const auto& section : binary_->sections()) {
        if (section.name != ".data" && section.name != ".rdata") {
            continue;
        }
        
        if (section.file_size == 0) {
            continue;
        }
        
        auto data_opt = binary_->read(section.virtual_address, section.file_size);
        if (!data_opt || data_opt->empty()) {
            continue;
        }
        
        const auto& data = *data_opt;
        
        auto* data_type = llvm::ArrayType::get(
            llvm::Type::getInt8Ty(ctx),
            data.size()
        );
        
        std::vector<llvm::Constant*> bytes;
        bytes.reserve(data.size());
        for (auto byte : data) {
            bytes.push_back(llvm::ConstantInt::get(llvm::Type::getInt8Ty(ctx), 
                static_cast<unsigned char>(byte), false));
        }
        
        auto* initializer = llvm::ConstantArray::get(data_type, bytes);
        
        auto* global = new llvm::GlobalVariable(
            *module,
            data_type,
            section.name == ".rdata",
            llvm::GlobalValue::ExternalLinkage,
            initializer,
            std::format("__picanha_section_{}", section.name.substr(1))
        );
        
        global->setAlignment(llvm::Align(16));
        has_data = true;
    }
    
    if (!has_data) {
        return {};
    }
    
    std::string ir_text;
    llvm::raw_string_ostream os(ir_text);
    module->print(os, nullptr);
    os.flush();
    
    return ir_text;
}

bool ExportLiftService::merge_into_module(
    llvm::Module& target,
    llvm::Module& source,
    const std::string& main_func_name
) {
    // Use LLVM's Linker to merge modules
    llvm::Linker linker(target);
    
    // Link the source module
    if (linker.linkInModule(llvm::CloneModule(source))) {
        return false;
    }
    
    return true;
}

} // namespace picanha::lift
