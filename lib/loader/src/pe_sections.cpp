#include "picanha/loader/pe/pe_sections.hpp"
#include <algorithm>
#include <cstdio>

namespace picanha::loader::pe {

MemoryPermissions section_flags_to_permissions(SectionFlags flags) {
    MemoryPermissions perms = MemoryPermissions::None;

    if (has_flag(flags, SectionFlags::MemRead)) {
        perms = perms | MemoryPermissions::Read;
    }
    if (has_flag(flags, SectionFlags::MemWrite)) {
        perms = perms | MemoryPermissions::Write;
    }
    if (has_flag(flags, SectionFlags::MemExecute)) {
        perms = perms | MemoryPermissions::Execute;
    }

    return perms;
}

std::vector<Section> build_sections(const PEInfo& info) {
    std::vector<Section> result;
    result.reserve(info.sections.size());

    for (SectionIndex i = 0; i < info.sections.size(); ++i) {
        const auto& header = info.sections[i];

        Section section;

        // Get section name, use segXXX format for unnamed sections
        std::string name = std::string(header.name());
        if (name.empty() || name[0] == '\0') {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "seg%03u", static_cast<unsigned>(i));
            section.name = buf;
        } else {
            section.name = std::move(name);
        }

        section.rva = header.VirtualAddress;
        section.virtual_address = info.image_base + header.VirtualAddress;
        section.virtual_size = header.VirtualSize > 0 ? header.VirtualSize : header.SizeOfRawData;
        section.file_offset = header.PointerToRawData;
        section.file_size = header.SizeOfRawData;
        section.permissions = section_flags_to_permissions(header.Characteristics);
        section.flags = header.Characteristics;
        section.index = i;

        result.push_back(std::move(section));
    }

    // Sort sections by virtual address for proper iteration
    std::sort(result.begin(), result.end(), [](const Section& a, const Section& b) {
        return a.virtual_address < b.virtual_address;
    });

    return result;
}

} // namespace picanha::loader::pe
