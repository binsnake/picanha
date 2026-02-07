#include "picanha/loader/pe/pe_relocations.hpp"

namespace picanha::loader::pe {

std::vector<const Relocation*> RelocationInfo::find_in_range(Address start, Address end) const {
    std::vector<const Relocation*> result;
    for (const auto& reloc : relocations) {
        if (reloc.address >= start && reloc.address < end) {
            result.push_back(&reloc);
        }
    }
    return result;
}

const Relocation* RelocationInfo::find_at(Address addr) const {
    for (const auto& reloc : relocations) {
        if (reloc.address == addr) {
            return &reloc;
        }
    }
    return nullptr;
}

Result<RelocationInfo> parse_relocations(const PEParser& parser) {
    const auto& info = parser.info();
    const auto& reloc_dir = info.data_directory(DataDirectoryIndex::BaseReloc);

    if (!reloc_dir.is_present()) {
        return RelocationInfo{}; // No relocations (stripped or position-dependent)
    }

    RelocationInfo result;

    RVA current_rva = reloc_dir.VirtualAddress;
    RVA end_rva = current_rva + reloc_dir.Size;

    while (current_rva < end_rva) {
        auto block_data = parser.get_data_at_rva(current_rva, sizeof(BaseRelocationBlock));
        if (!block_data) {
            break;
        }

        SpanReader block_reader(*block_data);
        auto block = block_reader.read_struct<BaseRelocationBlock>();
        if (!block || block->SizeOfBlock == 0) {
            break;
        }

        // Calculate number of entries
        std::size_t num_entries = (block->SizeOfBlock - sizeof(BaseRelocationBlock)) / sizeof(std::uint16_t);

        // Read entries
        auto entries_data = parser.get_data_at_rva(
            current_rva + sizeof(BaseRelocationBlock),
            num_entries * sizeof(std::uint16_t)
        );

        if (entries_data) {
            SpanReader entries_reader(*entries_data);
            for (std::size_t i = 0; i < num_entries; ++i) {
                auto entry_val = entries_reader.read_u16();
                if (!entry_val) break;

                RelocationEntry entry{*entry_val};
                RelocationType type = entry.type();

                // Skip padding entries
                if (type == RelocationType::Absolute) {
                    continue;
                }

                Relocation reloc;
                reloc.rva = block->VirtualAddress + entry.offset();
                reloc.type = type;
                reloc.address = parser.rva_to_va(reloc.rva);

                result.relocations.push_back(reloc);
            }
        }

        current_rva += block->SizeOfBlock;
    }

    return result;
}

} // namespace picanha::loader::pe
