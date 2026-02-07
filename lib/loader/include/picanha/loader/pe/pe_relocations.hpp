#pragma once

#include "picanha/loader/pe/pe_types.hpp"
#include "picanha/loader/pe/pe_parser.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/result.hpp>
#include <vector>

namespace picanha::loader::pe {

// Single relocation entry
struct Relocation {
    RVA rva;                    // RVA that needs relocation
    RelocationType type;        // Relocation type
    Address address;            // VA that needs relocation

    [[nodiscard]] std::size_t size() const noexcept {
        switch (type) {
            case RelocationType::HighLow:  return 4;
            case RelocationType::Dir64:    return 8;
            case RelocationType::High:     return 2;
            case RelocationType::Low:      return 2;
            default:                       return 0;
        }
    }
};

// All relocations
struct RelocationInfo {
    std::vector<Relocation> relocations;

    // Find relocations in an address range
    [[nodiscard]] std::vector<const Relocation*> find_in_range(Address start, Address end) const;

    // Check if an address has a relocation
    [[nodiscard]] const Relocation* find_at(Address addr) const;
};

// Parse base relocation directory
[[nodiscard]] Result<RelocationInfo> parse_relocations(const PEParser& parser);

} // namespace picanha::loader::pe
