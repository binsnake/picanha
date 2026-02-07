#pragma once

#include <picanha/core/types.hpp>
#include <memory>
#include <string>
#include <optional>

// Forward declarations
namespace llvm {
class Module;
class LLVMContext;
} // namespace llvm

namespace clang {
class ASTUnit;
} // namespace clang

namespace picanha::lift {

class LiftingContext;
class LiftedFunction;

// Result of decompilation
struct DecompilationResult {
    std::string code;           // The decompiled C code
    bool success{false};
    std::string error_message;
};

// Configuration for decompilation
struct DecompilationConfig {
    bool lower_switches{false};      // Convert switch to if-else chains
    bool remove_phi_nodes{false};    // Remove PHI nodes before decompilation
    bool format_output{true};        // Format the output C code
};

// Service for decompiling LLVM IR to C code using Rellic
class DecompilationService {
public:
    explicit DecompilationService(LiftingContext* context);
    ~DecompilationService();

    // Non-copyable
    DecompilationService(const DecompilationService&) = delete;
    DecompilationService& operator=(const DecompilationService&) = delete;

    // Check if decompilation is available (Rellic was built)
    [[nodiscard]] static bool is_available() noexcept;

    // Decompile an LLVM module to C code
    [[nodiscard]] DecompilationResult decompile(
        llvm::Module* module,
        const DecompilationConfig& config = {});

    // Decompile a lifted function to C code
    [[nodiscard]] DecompilationResult decompile_function(
        const LiftedFunction& func,
        const DecompilationConfig& config = {});

    // Decompile a lifted function by cloning its module
    // This is safer as it doesn't consume the original module
    [[nodiscard]] DecompilationResult decompile_function_copy(
        const LiftedFunction& func,
        const DecompilationConfig& config = {});

    // Get the last error message
    [[nodiscard]] const std::string& last_error() const noexcept { return last_error_; }

private:
    LiftingContext* context_;
    std::string last_error_;
};

} // namespace picanha::lift
