#include "picanha/loader/pe/pe_imports.hpp"

namespace picanha::loader::pe {

const ImportedFunction* ImportedModule::find_by_name(std::string_view name) const {
    for (const auto& func : functions) {
        if (func.name == name) {
            return &func;
        }
    }
    return nullptr;
}

const ImportedFunction* ImportedModule::find_by_ordinal(std::uint16_t ordinal) const {
    for (const auto& func : functions) {
        if (func.by_ordinal && func.ordinal == ordinal) {
            return &func;
        }
    }
    return nullptr;
}

const ImportedModule* ImportInfo::find_module(std::string_view name) const {
    for (const auto& mod : modules) {
        if (mod.name == name) {
            return &mod;
        }
    }
    return nullptr;
}

std::pair<const ImportedModule*, const ImportedFunction*>
ImportInfo::find_function(std::string_view dll_name, std::string_view func_name) const {
    const auto* mod = find_module(dll_name);
    if (!mod) {
        return {nullptr, nullptr};
    }
    return {mod, mod->find_by_name(func_name)};
}

std::size_t ImportInfo::total_functions() const noexcept {
    std::size_t count = 0;
    for (const auto& mod : modules) {
        count += mod.functions.size();
    }
    return count;
}

Result<ImportInfo> parse_imports(const PEParser& parser) {
    const auto& info = parser.info();
    const auto& import_dir = info.data_directory(DataDirectoryIndex::Import);

    if (!import_dir.is_present()) {
        return ImportInfo{}; // No imports
    }

    ImportInfo result;

    // Ordinal flag for imports
    const std::uint64_t ordinal_flag = info.is_pe32_plus ? 0x8000000000000000ULL : 0x80000000ULL;
    const std::size_t thunk_size = info.is_pe32_plus ? 8 : 4;

    // Iterate import descriptors
    RVA desc_rva = import_dir.VirtualAddress;

    while (true) {
        auto desc_data = parser.get_data_at_rva(desc_rva, sizeof(ImportDescriptor));
        if (!desc_data) {
            break;
        }

        SpanReader desc_reader(*desc_data);
        auto desc = desc_reader.read_struct<ImportDescriptor>();
        if (!desc || desc->is_null()) {
            break;
        }

        ImportedModule module;
        module.timestamp = desc->TimeDateStamp;
        module.iat_rva = desc->FirstThunk;
        module.int_rva = desc->OriginalFirstThunk != 0 ? desc->OriginalFirstThunk : desc->FirstThunk;

        // Read DLL name
        if (desc->Name != 0) {
            auto name = parser.read_string_at_rva(desc->Name);
            if (name) {
                module.name = std::string(*name);
            }
        }

        // Read imported functions
        RVA int_entry_rva = module.int_rva;
        RVA iat_entry_rva = module.iat_rva;

        while (true) {
            std::uint64_t thunk_value = 0;

            auto thunk_data = parser.get_data_at_rva(int_entry_rva, thunk_size);
            if (!thunk_data) {
                break;
            }

            SpanReader thunk_reader(*thunk_data);
            if (info.is_pe32_plus) {
                auto val = thunk_reader.read_u64();
                thunk_value = val.value_or(0);
            } else {
                auto val = thunk_reader.read_u32();
                thunk_value = val.value_or(0);
            }

            if (thunk_value == 0) {
                break; // End of thunk array
            }

            ImportedFunction func;
            func.int_rva = int_entry_rva;
            func.iat_rva = iat_entry_rva;

            if (thunk_value & ordinal_flag) {
                // Import by ordinal
                func.by_ordinal = true;
                func.ordinal = static_cast<std::uint16_t>(thunk_value & 0xFFFF);
                func.hint = 0;
            } else {
                // Import by name
                func.by_ordinal = false;
                func.ordinal = 0;

                RVA hint_name_rva = static_cast<RVA>(thunk_value);
                auto hint_data = parser.get_data_at_rva(hint_name_rva, sizeof(ImportByName));
                if (hint_data) {
                    SpanReader hint_reader(*hint_data);
                    auto hint = hint_reader.read_u16();
                    func.hint = hint.value_or(0);

                    // Name follows hint
                    auto name = parser.read_string_at_rva(hint_name_rva + 2);
                    if (name) {
                        func.name = std::string(*name);
                    }
                }
            }

            module.functions.push_back(std::move(func));

            int_entry_rva += static_cast<RVA>(thunk_size);
            iat_entry_rva += static_cast<RVA>(thunk_size);
        }

        result.modules.push_back(std::move(module));
        desc_rva += sizeof(ImportDescriptor);
    }

    return result;
}

Result<DelayImportInfo> parse_delay_imports(const PEParser& parser) {
    const auto& info = parser.info();
    const auto& delay_import_dir = info.data_directory(DataDirectoryIndex::DelayImport);

    if (!delay_import_dir.is_present()) {
        return DelayImportInfo{}; // No delay imports
    }

    // Delay import parsing follows similar pattern to regular imports
    // but with ImgDelayDescr structure instead of ImportDescriptor

    DelayImportInfo result;
    // TODO: Implement delay import parsing if needed

    return result;
}

} // namespace picanha::loader::pe
