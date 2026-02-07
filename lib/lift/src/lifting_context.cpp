#include <picanha/lift/lifting_context.hpp>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/TargetSelect.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>
#include <remill/BC/IntrinsicTable.h>

namespace picanha::lift {

LiftingContext::LiftingContext()
    : context_(std::make_unique<llvm::LLVMContext>())
{
    // Initialize LLVM targets (needed for code generation)
    static bool llvm_initialized = false;
    if (!llvm_initialized) {
        llvm::InitializeNativeTarget();
        llvm::InitializeNativeTargetAsmPrinter();
        llvm::InitializeNativeTargetAsmParser();
        llvm_initialized = true;
    }
}

LiftingContext::~LiftingContext() = default;

bool LiftingContext::initialize_x86_64_windows() {
    return initialize_arch("windows", "amd64_avx");
}

bool LiftingContext::initialize_x86_64_linux() {
    return initialize_arch("linux", "amd64");
}

bool LiftingContext::initialize_arch(const std::string& os_name,
                                      const std::string& arch_name) {
    if (initialized_) {
        error_ = "Already initialized";
        return false;
    }

    try {
        // Get the remill architecture
        arch_ = remill::Arch::Get(*context_, os_name, arch_name);
        if (!arch_) {
            error_ = "Failed to get remill architecture for " + os_name + "/" + arch_name;
            return false;
        }

        // Load the architecture semantics bitcode
        // This is required before we can use TraceLifter
        semantics_module_ = remill::LoadArchSemantics(arch_.get());
        if (!semantics_module_) {
            error_ = "Failed to load semantics for " + arch_name;
            return false;
        }

        // Prepare the architecture with the semantics module
        // This initializes the intrinsics table
        arch_->PrepareModule(semantics_module_.get());

        initialized_ = true;
        return true;
    } catch (const std::exception& e) {
        error_ = std::string("Exception during initialization: ") + e.what();
        return false;
    }
}

llvm::LLVMContext& LiftingContext::context() {
    return *context_;
}

const llvm::LLVMContext& LiftingContext::context() const {
    return *context_;
}

std::unique_ptr<llvm::Module> LiftingContext::create_module(const std::string& name) {
    if (!initialized_) {
        return nullptr;
    }

    // Create a new module with the arch's semantics
    auto module = std::make_unique<llvm::Module>(name, *context_);

    // Prepare the module with remill's required declarations
    arch_->PrepareModule(module.get());

    return module;
}

std::unique_lock<std::mutex> LiftingContext::lock() {
    return std::unique_lock<std::mutex>(mutex_);
}

} // namespace picanha::lift
