#include "picanha/loader/pe/pe_exports.hpp"

namespace picanha::loader::pe {

const Export* ExportInfo::find_by_name(std::string_view name) const {
    for (const auto& exp : exports) {
        if (exp.name == name) {
            return &exp;
        }
    }
    return nullptr;
}

const Export* ExportInfo::find_by_ordinal(std::uint16_t ordinal) const {
    for (const auto& exp : exports) {
        if (exp.ordinal == ordinal) {
            return &exp;
        }
    }
    return nullptr;
}

const Export* ExportInfo::find_by_rva(RVA rva) const {
    for (const auto& exp : exports) {
        if (exp.rva == rva && !exp.is_forwarded) {
            return &exp;
        }
    }
    return nullptr;
}

Result<ExportInfo> parse_exports(const PEParser& parser) {
    const auto& info = parser.info();
    const auto& export_dir = info.data_directory(DataDirectoryIndex::Export);

    if (!export_dir.is_present()) {
        return ExportInfo{}; // No exports
    }

    auto export_data = parser.get_data_at_rva(export_dir.VirtualAddress, sizeof(ExportDirectory));
    if (!export_data) {
        return std::unexpected(parse_error("Failed to read export directory"));
    }

    SpanReader reader(*export_data);
    auto dir = reader.read_struct<ExportDirectory>();
    if (!dir) {
        return std::unexpected(parse_error("Failed to parse export directory"));
    }

    ExportInfo result;
    result.timestamp = dir->TimeDateStamp;
    result.ordinal_base = static_cast<std::uint16_t>(dir->Base);

    // Read DLL name
    if (dir->Name != 0) {
        auto name = parser.read_string_at_rva(dir->Name);
        if (name) {
            result.dll_name = std::string(*name);
        }
    }

    // Bounds for forwarded export detection
    RVA export_start = export_dir.VirtualAddress;
    RVA export_end = export_start + export_dir.Size;

    // Read function addresses
    std::vector<RVA> function_rvas;
    if (dir->AddressOfFunctions != 0 && dir->NumberOfFunctions > 0) {
        auto funcs_data = parser.get_data_at_rva(
            dir->AddressOfFunctions,
            dir->NumberOfFunctions * sizeof(std::uint32_t)
        );
        if (funcs_data) {
            SpanReader funcs_reader(*funcs_data);
            for (std::uint32_t i = 0; i < dir->NumberOfFunctions; ++i) {
                auto rva = funcs_reader.read_u32();
                function_rvas.push_back(rva.value_or(0));
            }
        }
    }

    // Read name ordinals
    std::vector<std::uint16_t> name_ordinals;
    if (dir->AddressOfNameOrdinals != 0 && dir->NumberOfNames > 0) {
        auto ordinals_data = parser.get_data_at_rva(
            dir->AddressOfNameOrdinals,
            dir->NumberOfNames * sizeof(std::uint16_t)
        );
        if (ordinals_data) {
            SpanReader ordinals_reader(*ordinals_data);
            for (std::uint32_t i = 0; i < dir->NumberOfNames; ++i) {
                auto ordinal = ordinals_reader.read_u16();
                name_ordinals.push_back(ordinal.value_or(0));
            }
        }
    }

    // Read names
    std::vector<std::string> names;
    if (dir->AddressOfNames != 0 && dir->NumberOfNames > 0) {
        auto names_data = parser.get_data_at_rva(
            dir->AddressOfNames,
            dir->NumberOfNames * sizeof(std::uint32_t)
        );
        if (names_data) {
            SpanReader names_reader(*names_data);
            for (std::uint32_t i = 0; i < dir->NumberOfNames; ++i) {
                auto name_rva = names_reader.read_u32();
                if (name_rva) {
                    auto name = parser.read_string_at_rva(*name_rva);
                    names.push_back(name ? std::string(*name) : "");
                } else {
                    names.push_back("");
                }
            }
        }
    }

    // Build export list
    result.exports.reserve(function_rvas.size());

    for (std::uint32_t i = 0; i < function_rvas.size(); ++i) {
        RVA func_rva = function_rvas[i];
        if (func_rva == 0) {
            continue; // Unused ordinal slot
        }

        Export exp;
        exp.ordinal = static_cast<std::uint16_t>(result.ordinal_base + i);
        exp.rva = func_rva;
        exp.address = parser.rva_to_va(func_rva);

        // Check if forwarded
        exp.is_forwarded = (func_rva >= export_start && func_rva < export_end);
        if (exp.is_forwarded) {
            auto forward = parser.read_string_at_rva(func_rva);
            if (forward) {
                exp.forward_name = std::string(*forward);
            }
        }

        // Find name for this ordinal
        for (std::size_t j = 0; j < name_ordinals.size(); ++j) {
            if (name_ordinals[j] == i && j < names.size()) {
                exp.name = names[j];
                break;
            }
        }

        result.exports.push_back(std::move(exp));
    }

    return result;
}

} // namespace picanha::loader::pe
