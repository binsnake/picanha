#pragma once

#include "picanha/loader/pe/pe_types.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/result.hpp>
#include <picanha/core/span.hpp>
#include <vector>
#include <span>
#include <string>
#include <optional>

namespace picanha::loader::pe {

// Parsed PE file information
struct PEInfo {
    // Header locations
    FileOffset dos_header_offset{0};
    FileOffset pe_header_offset{0};
    FileOffset optional_header_offset{0};
    FileOffset section_headers_offset{0};

    // COFF header fields
    MachineType machine{MachineType::Unknown};
    FileCharacteristics characteristics{FileCharacteristics::None};
    std::uint32_t timestamp{0};
    std::uint16_t num_sections{0};

    // Optional header fields
    bool is_pe32_plus{false};  // true = 64-bit, false = 32-bit
    Address image_base{0};
    Address entry_point_rva{0};
    std::uint32_t section_alignment{0};
    std::uint32_t file_alignment{0};
    std::uint32_t size_of_image{0};
    std::uint32_t size_of_headers{0};
    Subsystem subsystem{Subsystem::Unknown};
    DllCharacteristics dll_characteristics{DllCharacteristics::None};

    // Data directories
    std::array<DataDirectory, static_cast<std::size_t>(DataDirectoryIndex::Count)> data_directories{};

    // Section headers
    std::vector<SectionHeader> sections;

    // Computed values
    [[nodiscard]] Address entry_point() const noexcept {
        return image_base + entry_point_rva;
    }

    [[nodiscard]] bool is_dll() const noexcept {
        return has_flag(characteristics, FileCharacteristics::Dll);
    }

    [[nodiscard]] bool is_executable() const noexcept {
        return has_flag(characteristics, FileCharacteristics::ExecutableImage);
    }

    [[nodiscard]] bool is_large_address_aware() const noexcept {
        return has_flag(characteristics, FileCharacteristics::LargeAddressAware);
    }

    [[nodiscard]] bool has_aslr() const noexcept {
        return has_flag(dll_characteristics, DllCharacteristics::DynamicBase);
    }

    [[nodiscard]] bool has_dep() const noexcept {
        return has_flag(dll_characteristics, DllCharacteristics::NxCompat);
    }

    [[nodiscard]] bool has_cfg() const noexcept {
        return has_flag(dll_characteristics, DllCharacteristics::GuardCF);
    }

    [[nodiscard]] const DataDirectory& data_directory(DataDirectoryIndex index) const noexcept {
        return data_directories[static_cast<std::size_t>(index)];
    }

    [[nodiscard]] Bitness bitness() const noexcept {
        return is_pe32_plus ? Bitness::Bits64 : Bitness::Bits32;
    }
};

// PE Parser class
class PEParser {
public:
    explicit PEParser(ByteSpan data) noexcept;

    // Parse the PE headers
    [[nodiscard]] Result<PEInfo> parse();

    // RVA to file offset conversion
    [[nodiscard]] std::optional<FileOffset> rva_to_file_offset(RVA rva) const;

    // RVA to VA conversion
    [[nodiscard]] Address rva_to_va(RVA rva) const noexcept;

    // File offset to RVA conversion
    [[nodiscard]] std::optional<RVA> file_offset_to_rva(FileOffset offset) const;

    // Find section containing RVA
    [[nodiscard]] const SectionHeader* find_section_by_rva(RVA rva) const;

    // Find section by name
    [[nodiscard]] const SectionHeader* find_section_by_name(std::string_view name) const;

    // Get section data
    [[nodiscard]] std::optional<ByteSpan> get_section_data(const SectionHeader& section) const;

    // Get data at RVA
    [[nodiscard]] std::optional<ByteSpan> get_data_at_rva(RVA rva, std::size_t size) const;

    // Read null-terminated string at RVA
    [[nodiscard]] std::optional<std::string_view> read_string_at_rva(RVA rva) const;

    // Access parsed info
    [[nodiscard]] const PEInfo& info() const noexcept { return info_; }
    [[nodiscard]] bool is_parsed() const noexcept { return parsed_; }

private:
    Result<void> parse_dos_header();
    Result<void> parse_coff_header();
    Result<void> parse_optional_header();
    Result<void> parse_section_headers();

    ByteSpan data_;
    SpanReader reader_;
    PEInfo info_;
    bool parsed_{false};
};

// Utility functions
[[nodiscard]] bool is_valid_pe(ByteSpan data);
[[nodiscard]] std::string_view machine_type_to_string(MachineType machine);
[[nodiscard]] std::string_view subsystem_to_string(Subsystem subsystem);

} // namespace picanha::loader::pe
