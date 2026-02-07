#pragma once

#include "picanha/loader/pe/pe_types.hpp"
#include "picanha/loader/pe/pe_parser.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/result.hpp>
#include <vector>
#include <string>

namespace picanha::loader::pe {

// Single imported function
struct ImportedFunction {
    std::string name;           // Function name (empty if by ordinal)
    std::uint16_t hint;         // Loader hint
    std::uint16_t ordinal;      // Ordinal (if imported by ordinal)
    bool by_ordinal;            // True if imported by ordinal
    RVA iat_rva;                // RVA in Import Address Table
    RVA int_rva;                // RVA in Import Name Table

    [[nodiscard]] bool has_name() const noexcept { return !name.empty(); }
};

// Import from a single DLL
struct ImportedModule {
    std::string name;                           // DLL name
    std::vector<ImportedFunction> functions;    // Imported functions
    RVA iat_rva;                               // Start of IAT for this module
    RVA int_rva;                               // Start of INT for this module
    std::uint32_t timestamp;                    // Bound import timestamp

    // Find function by name
    [[nodiscard]] const ImportedFunction* find_by_name(std::string_view name) const;

    // Find function by ordinal
    [[nodiscard]] const ImportedFunction* find_by_ordinal(std::uint16_t ordinal) const;
};

// All imports
struct ImportInfo {
    std::vector<ImportedModule> modules;

    // Find module by name
    [[nodiscard]] const ImportedModule* find_module(std::string_view name) const;

    // Find function across all modules
    [[nodiscard]] std::pair<const ImportedModule*, const ImportedFunction*>
        find_function(std::string_view dll_name, std::string_view func_name) const;

    // Get total import count
    [[nodiscard]] std::size_t total_functions() const noexcept;
};

// Parse import directory
[[nodiscard]] Result<ImportInfo> parse_imports(const PEParser& parser);

// Delay-loaded import
struct DelayImportedModule {
    std::string name;
    std::vector<ImportedFunction> functions;
    RVA module_handle_rva;      // RVA of module handle
    RVA iat_rva;                // Delay IAT RVA
    RVA int_rva;                // Delay INT RVA
    RVA bound_iat_rva;          // Bound delay IAT RVA
    RVA unload_iat_rva;         // Unload delay IAT RVA
    std::uint32_t timestamp;
};

struct DelayImportInfo {
    std::vector<DelayImportedModule> modules;
};

// Parse delay import directory
[[nodiscard]] Result<DelayImportInfo> parse_delay_imports(const PEParser& parser);

} // namespace picanha::loader::pe
