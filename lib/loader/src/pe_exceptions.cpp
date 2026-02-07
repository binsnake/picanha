#include "picanha/loader/pe/pe_exceptions.hpp"
#include <algorithm>

namespace picanha::loader::pe {

const FunctionEntry* ExceptionInfo::find_containing(Address addr) const {
    // Functions should be sorted by begin_address for binary search
    auto it = std::lower_bound(functions.begin(), functions.end(), addr,
        [](const FunctionEntry& entry, Address a) {
            return entry.end_address <= a;
        });

    if (it != functions.end() && it->contains(addr)) {
        return &(*it);
    }
    return nullptr;
}

const FunctionEntry* ExceptionInfo::find_containing_rva(RVA rva) const {
    auto it = std::lower_bound(functions.begin(), functions.end(), rva,
        [](const FunctionEntry& entry, RVA r) {
            return entry.end_rva <= r;
        });

    if (it != functions.end() && it->contains_rva(rva)) {
        return &(*it);
    }
    return nullptr;
}

const FunctionEntry* ExceptionInfo::find_by_start(Address addr) const {
    auto it = std::lower_bound(functions.begin(), functions.end(), addr,
        [](const FunctionEntry& entry, Address a) {
            return entry.begin_address < a;
        });

    if (it != functions.end() && it->begin_address == addr) {
        return &(*it);
    }
    return nullptr;
}

const FunctionEntry* ExceptionInfo::binary_search_rva(RVA rva) const {
    return find_containing_rva(rva);
}

// Helper to check if an unwind info entry is chained
static bool is_chained_unwind(const PEParser& parser, RVA unwind_info_rva) {
    auto data = parser.get_data_at_rva(unwind_info_rva, sizeof(UnwindInfo));
    if (!data || data->size() < 1) {
        return false;
    }

    // First byte contains version (3 bits) and flags (5 bits)
    std::uint8_t first_byte = (*data)[0];
    std::uint8_t flags = (first_byte >> 3) & 0x1F;

    return (flags & static_cast<std::uint8_t>(UnwindFlags::ChainInfo)) != 0;
}

Result<ExceptionInfo> parse_exceptions(const PEParser& parser) {
    const auto& info = parser.info();

    // Exception directory only present on x64
    if (!info.is_pe32_plus || info.machine != MachineType::AMD64) {
        return ExceptionInfo{}; // No exception info for 32-bit or non-x64
    }

    const auto& exception_dir = info.data_directory(DataDirectoryIndex::Exception);
    if (!exception_dir.is_present()) {
        return ExceptionInfo{};
    }

    ExceptionInfo result;

    // Calculate number of entries
    std::size_t num_entries = exception_dir.Size / sizeof(RuntimeFunction);
    result.functions.reserve(num_entries);

    auto entries_data = parser.get_data_at_rva(exception_dir.VirtualAddress, exception_dir.Size);
    if (!entries_data) {
        return std::unexpected(parse_error("Failed to read exception directory"));
    }

    SpanReader reader(*entries_data);

    for (std::size_t i = 0; i < num_entries; ++i) {
        auto rf = reader.read_struct<RuntimeFunction>();
        if (!rf) {
            break;
        }

        // Skip entries with zero addresses (shouldn't happen but be safe)
        if (rf->BeginAddress == 0 && rf->EndAddress == 0) {
            continue;
        }

        // Skip chained entries - they're fragments of other functions, not independent functions
        // A chained RUNTIME_FUNCTION's unwind info has UNW_FLAG_CHAININFO set and points to
        // another RUNTIME_FUNCTION that describes the primary function
        if (is_chained_unwind(parser, rf->UnwindInfoAddress)) {
            continue;
        }

        FunctionEntry entry;
        entry.begin_rva = rf->BeginAddress;
        entry.end_rva = rf->EndAddress;
        entry.unwind_info_rva = rf->UnwindInfoAddress;
        entry.begin_address = parser.rva_to_va(rf->BeginAddress);
        entry.end_address = parser.rva_to_va(rf->EndAddress);

        result.functions.push_back(entry);
    }

    // Sort by begin address for binary search
    std::sort(result.functions.begin(), result.functions.end(),
        [](const FunctionEntry& a, const FunctionEntry& b) {
            return a.begin_rva < b.begin_rva;
        });

    // Remove duplicates (same begin_rva, keep the one with larger extent)
    auto it = std::unique(result.functions.begin(), result.functions.end(),
        [](const FunctionEntry& a, const FunctionEntry& b) {
            return a.begin_rva == b.begin_rva;
        });
    result.functions.erase(it, result.functions.end());

    return result;
}

Result<UnwindData> parse_unwind_info(const PEParser& parser, RVA unwind_info_rva) {
    auto data = parser.get_data_at_rva(unwind_info_rva, sizeof(UnwindInfo));
    if (!data) {
        return std::unexpected(parse_error("Failed to read unwind info"));
    }

    SpanReader reader(*data);
    auto unwind = reader.read_struct<UnwindInfo>();
    if (!unwind) {
        return std::unexpected(parse_error("Failed to parse unwind info"));
    }

    UnwindData result;
    result.version = unwind->version();
    result.flags = unwind->flags();
    result.size_of_prolog = unwind->SizeOfProlog;
    result.frame_register = unwind->frame_register();
    result.frame_offset = unwind->frame_offset();
    result.exception_handler_rva = 0;
    result.chained_info_rva = 0;

    // If there's handler data, it follows the unwind codes
    // The unwind codes are variable length, we'd need to parse them
    // to find the handler data. For now, we skip this.

    return result;
}

} // namespace picanha::loader::pe
