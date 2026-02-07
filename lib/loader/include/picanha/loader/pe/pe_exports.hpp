#pragma once

#include "picanha/loader/pe/pe_types.hpp"
#include "picanha/loader/pe/pe_parser.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/result.hpp>
#include <vector>
#include <string>
#include <optional>

namespace picanha::loader::pe {

// Exported function/data
struct Export {
    std::string name;           // Export name (empty if ordinal-only)
    std::uint16_t ordinal;      // Export ordinal
    RVA rva;                    // RVA of export
    Address address;            // VA of export
    bool is_forwarded;          // True if forwarded to another DLL
    std::string forward_name;   // Forwarded name (e.g., "NTDLL.RtlAllocateHeap")

    [[nodiscard]] bool has_name() const noexcept { return !name.empty(); }
};

// Parsed export directory
struct ExportInfo {
    std::string dll_name;
    std::uint32_t timestamp;
    std::uint16_t ordinal_base;
    std::vector<Export> exports;

    // Find export by name
    [[nodiscard]] const Export* find_by_name(std::string_view name) const;

    // Find export by ordinal
    [[nodiscard]] const Export* find_by_ordinal(std::uint16_t ordinal) const;

    // Find export by RVA
    [[nodiscard]] const Export* find_by_rva(RVA rva) const;
};

// Parse export directory
[[nodiscard]] Result<ExportInfo> parse_exports(const PEParser& parser);

} // namespace picanha::loader::pe
