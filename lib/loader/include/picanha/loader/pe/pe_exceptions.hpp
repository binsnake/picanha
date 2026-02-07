#pragma once

#include "picanha/loader/pe/pe_types.hpp"
#include "picanha/loader/pe/pe_parser.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/result.hpp>
#include <vector>

namespace picanha::loader::pe {

// Runtime function (from exception directory)
// This is extremely valuable for function boundary detection on x64
struct FunctionEntry {
    RVA begin_rva;              // Start of function
    RVA end_rva;                // End of function
    RVA unwind_info_rva;        // Unwind info RVA
    Address begin_address;      // VA of function start
    Address end_address;        // VA of function end

    [[nodiscard]] Size size() const noexcept {
        return end_rva - begin_rva;
    }

    [[nodiscard]] AddressRange range() const noexcept {
        return {begin_address, end_address};
    }

    [[nodiscard]] bool contains(Address addr) const noexcept {
        return addr >= begin_address && addr < end_address;
    }

    [[nodiscard]] bool contains_rva(RVA rva) const noexcept {
        return rva >= begin_rva && rva < end_rva;
    }
};

// Parsed unwind info
struct UnwindData {
    std::uint8_t version;
    std::uint8_t flags;
    std::uint8_t size_of_prolog;
    std::uint8_t frame_register;
    std::uint8_t frame_offset;

    // Handler info (if flags indicate handler present)
    RVA exception_handler_rva;
    RVA chained_info_rva;

    [[nodiscard]] bool has_exception_handler() const noexcept {
        return (flags & static_cast<std::uint8_t>(UnwindFlags::Ehandler)) != 0;
    }

    [[nodiscard]] bool has_termination_handler() const noexcept {
        return (flags & static_cast<std::uint8_t>(UnwindFlags::Uhandler)) != 0;
    }

    [[nodiscard]] bool is_chained() const noexcept {
        return (flags & static_cast<std::uint8_t>(UnwindFlags::ChainInfo)) != 0;
    }
};

// All exception/runtime function entries
struct ExceptionInfo {
    std::vector<FunctionEntry> functions;

    // Find function containing an address
    [[nodiscard]] const FunctionEntry* find_containing(Address addr) const;

    // Find function containing an RVA
    [[nodiscard]] const FunctionEntry* find_containing_rva(RVA rva) const;

    // Find function by start address
    [[nodiscard]] const FunctionEntry* find_by_start(Address addr) const;

    // Binary search for function (entries are sorted)
    [[nodiscard]] const FunctionEntry* binary_search_rva(RVA rva) const;
};

// Parse exception directory (x64 RUNTIME_FUNCTION array)
[[nodiscard]] Result<ExceptionInfo> parse_exceptions(const PEParser& parser);

// Parse unwind info for a function
[[nodiscard]] Result<UnwindData> parse_unwind_info(const PEParser& parser, RVA unwind_info_rva);

} // namespace picanha::loader::pe
