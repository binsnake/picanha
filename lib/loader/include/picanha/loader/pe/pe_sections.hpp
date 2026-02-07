#pragma once

#include "picanha/loader/pe/pe_types.hpp"
#include "picanha/loader/pe/pe_parser.hpp"
#include <picanha/core/types.hpp>
#include <vector>
#include <string>

namespace picanha::loader::pe {

// High-level section representation
struct Section {
    std::string name;
    Address virtual_address;     // VA (ImageBase + RVA)
    RVA rva;                     // Relative Virtual Address
    Size virtual_size;           // Size in memory
    FileOffset file_offset;      // Offset in file
    Size file_size;              // Size in file
    MemoryPermissions permissions;
    SectionFlags flags;
    SectionIndex index;

    [[nodiscard]] AddressRange address_range() const noexcept {
        return {virtual_address, virtual_address + virtual_size};
    }

    [[nodiscard]] bool contains_va(Address va) const noexcept {
        return va >= virtual_address && va < virtual_address + virtual_size;
    }

    [[nodiscard]] bool contains_rva(RVA r) const noexcept {
        return r >= rva && r < rva + virtual_size;
    }

    [[nodiscard]] bool is_executable() const noexcept {
        return has_permission(permissions, MemoryPermissions::Execute);
    }

    [[nodiscard]] bool is_writable() const noexcept {
        return has_permission(permissions, MemoryPermissions::Write);
    }

    [[nodiscard]] bool contains_code() const noexcept {
        return has_flag(flags, SectionFlags::CntCode);
    }
};

// Build Section vector from PEInfo
[[nodiscard]] std::vector<Section> build_sections(const PEInfo& info);

// Convert SectionFlags to MemoryPermissions
[[nodiscard]] MemoryPermissions section_flags_to_permissions(SectionFlags flags);

} // namespace picanha::loader::pe
