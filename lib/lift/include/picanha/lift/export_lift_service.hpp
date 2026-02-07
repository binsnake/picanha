#pragma once

#include <picanha/lift/lifting_service.hpp>
#include <picanha/lift/types.hpp>
#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>
#include <memory>
#include <string>
#include <vector>
#include <unordered_set>
#include <fstream>

namespace llvm {
class Module;
class Function;
} // namespace llvm

namespace picanha::lift {

// Configuration for export lifting
struct ExportLiftConfig {
    // Optimization level to apply (default: O0 for maximum compatibility)
    OptimizationLevel opt_level = OptimizationLevel::O0;
    
    // Whether to recursively lift dependencies (called functions)
    bool include_dependencies = false;
    
    // Whether to include data sections (.data, .rdata)
    bool include_data_sections = false;
    
    // Maximum recursion depth for dependency lifting (prevents infinite loops)
    std::size_t max_dependency_depth = 10;
    
    // Entry point symbol name for linking (defaults to lifted function name if empty)
    std::string entry_point_name;
    
    // Whether to automatically compile and link the output
    bool auto_compile = false;
    
    // Output executable name (only used if auto_compile is true)
    std::string output_executable;
    
    // Path to remill runtime library for linking
    std::string remill_lib_path;
};

// Result of an export lift operation
struct ExportLiftResult {
    bool success = false;
    std::string error_message;
    
    // The main lifted module (compile-ready LLVM IR)
    std::string code_ir;
    
    // Optional data section module (if include_data_sections is true)
    std::string data_ir;
    
    // List of lifted function addresses (main + dependencies)
    std::vector<Address> lifted_functions;
    
    // List of data sections included
    std::vector<std::string> included_data_sections;
    
    // Compilation result (if auto_compile is enabled)
    bool compilation_success = false;
    std::string compilation_output;
    std::string output_executable_path;
    
    // List of link dependencies that need to be resolved
    std::vector<std::string> unresolved_symbols;
};

// Service for exporting lifted functions as compile-ready LLVM IR
// Unlike normal lifting which strips remill runtime, this includes everything needed
// to compile the output with clang
class ExportLiftService {
public:
    explicit ExportLiftService(std::shared_ptr<loader::Binary> binary);
    ~ExportLiftService();

    // Non-copyable, non-movable
    ExportLiftService(const ExportLiftService&) = delete;
    ExportLiftService& operator=(const ExportLiftService&) = delete;

    // Initialize the service (must be called before export)
    [[nodiscard]] bool initialize();
    [[nodiscard]] bool is_initialized() const noexcept { return initialized_; }
    [[nodiscard]] const std::string& error_message() const noexcept { return error_; }

    // Export a function as compile-ready LLVM IR
    // This includes remill runtime functions and marks the target as used
    [[nodiscard]] ExportLiftResult export_function(Address entry, const ExportLiftConfig& config);

    // Access underlying lifting service
    [[nodiscard]] LiftingService* lifting_service() noexcept { return lifting_service_.get(); }
    [[nodiscard]] const LiftingService* lifting_service() const noexcept { return lifting_service_.get(); }

    // Compile and link the exported IR
    [[nodiscard]] ExportLiftResult compile_and_link(ExportLiftResult& result, const ExportLiftConfig& config);

private:
    // Implementation of export with dependency tracking
    [[nodiscard]] ExportLiftResult export_function_impl(
        Address entry, 
        const ExportLiftConfig& config,
        std::unordered_set<Address>& visited,
        std::size_t depth
    );

    // Collect called addresses from a lifted function for dependency lifting
    [[nodiscard]] std::vector<Address> collect_called_addresses(llvm::Function* func);

    // Mark functions as used to prevent DCE during optimization
    void mark_functions_as_used(llvm::Module& module, const std::vector<std::string>& func_names);

    // Generate data section module with raw data
    [[nodiscard]] std::string generate_data_section_module();

    // Merge multiple lifted functions into a single module
    [[nodiscard]] bool merge_into_module(
        llvm::Module& target,
        llvm::Module& source,
        const std::string& main_func_name
    );

    std::shared_ptr<loader::Binary> binary_;
    std::unique_ptr<LiftingService> lifting_service_;
    bool initialized_ = false;
    std::string error_;
};

} // namespace picanha::lift
