#pragma once

#include <picanha/core/types.hpp>
#include <memory>
#include <mutex>
#include <string>

// Forward declarations for LLVM types
namespace llvm {
class LLVMContext;
class Module;
} // namespace llvm

// Forward declarations for remill types
namespace remill {
class Arch;
} // namespace remill

namespace picanha::lift {

// Thread-safe LLVM context and remill architecture management
class LiftingContext {
public:
    LiftingContext();
    ~LiftingContext();

    // Non-copyable, non-movable (owns LLVM context)
    LiftingContext(const LiftingContext&) = delete;
    LiftingContext& operator=(const LiftingContext&) = delete;
    LiftingContext(LiftingContext&&) = delete;
    LiftingContext& operator=(LiftingContext&&) = delete;

    // Initialize for a specific architecture
    // Returns true on success
    [[nodiscard]] bool initialize_x86_64_windows();
    [[nodiscard]] bool initialize_x86_64_linux();

    // Check if initialized
    [[nodiscard]] bool is_initialized() const noexcept { return initialized_; }

    // Get the LLVM context (NOT thread-safe - use lock() for multi-threaded access)
    [[nodiscard]] llvm::LLVMContext& context();
    [[nodiscard]] const llvm::LLVMContext& context() const;

    // Get the remill architecture
    [[nodiscard]] const remill::Arch* arch() const noexcept { return arch_.get(); }

    // Get the semantics module (contains intrinsics and lifted instruction semantics)
    [[nodiscard]] llvm::Module* semantics_module() const noexcept { return semantics_module_.get(); }

    // Create a new LLVM module for lifting
    // The module is owned by the caller
    [[nodiscard]] std::unique_ptr<llvm::Module> create_module(const std::string& name);

    // Thread-safe access to the context
    // Use this when accessing the context from multiple threads
    [[nodiscard]] std::unique_lock<std::mutex> lock();

    // Get error message if initialization failed
    [[nodiscard]] const std::string& error_message() const noexcept { return error_; }

private:
    bool initialize_arch(const std::string& os_name, const std::string& arch_name);

    std::unique_ptr<llvm::LLVMContext> context_;
    std::shared_ptr<const remill::Arch> arch_;
    std::unique_ptr<llvm::Module> semantics_module_;  // Holds instruction semantics
    mutable std::mutex mutex_;
    bool initialized_{false};
    std::string error_;
};

} // namespace picanha::lift
