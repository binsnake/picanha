#include "picanha/loader/pe/pe_parser.hpp"
#include <cstring>
#include <algorithm>

namespace picanha::loader::pe {

PEParser::PEParser(ByteSpan data) noexcept
    : data_(data)
    , reader_(data)
{}

Result<PEInfo> PEParser::parse() {
    if (parsed_) {
        return info_;
    }

    auto result = parse_dos_header();
    if (!result) return std::unexpected(result.error());

    result = parse_coff_header();
    if (!result) return std::unexpected(result.error());

    result = parse_optional_header();
    if (!result) return std::unexpected(result.error());

    result = parse_section_headers();
    if (!result) return std::unexpected(result.error());

    parsed_ = true;
    return info_;
}

Result<void> PEParser::parse_dos_header() {
    info_.dos_header_offset = 0;
    reader_.seek(0);

    auto dos_header = reader_.read_struct<DosHeader>();
    if (!dos_header) {
        return std::unexpected(parse_error("Failed to read DOS header"));
    }

    if (dos_header->e_magic != DOS_SIGNATURE) {
        return std::unexpected(parse_error("Invalid DOS signature"));
    }

    if (dos_header->e_lfanew < 0 ||
        static_cast<std::size_t>(dos_header->e_lfanew) >= data_.size()) {
        return std::unexpected(parse_error("Invalid PE header offset"));
    }

    info_.pe_header_offset = static_cast<FileOffset>(dos_header->e_lfanew);
    return {};
}

Result<void> PEParser::parse_coff_header() {
    reader_.seek(info_.pe_header_offset);

    // Read PE signature
    auto signature = reader_.read_u32();
    if (!signature || *signature != PE_SIGNATURE) {
        return std::unexpected(parse_error("Invalid PE signature"));
    }

    // Read COFF header
    auto coff_header = reader_.read_struct<CoffHeader>();
    if (!coff_header) {
        return std::unexpected(parse_error("Failed to read COFF header"));
    }

    info_.machine = coff_header->Machine;
    info_.num_sections = coff_header->NumberOfSections;
    info_.timestamp = coff_header->TimeDateStamp;
    info_.characteristics = coff_header->Characteristics;

    info_.optional_header_offset = reader_.position();

    // Validate machine type
    switch (info_.machine) {
        case MachineType::AMD64:
        case MachineType::I386:
        case MachineType::ARM64:
        case MachineType::ARM:
        case MachineType::ARMNT:
            break;
        default:
            return std::unexpected(parse_error("Unsupported machine type"));
    }

    return {};
}

Result<void> PEParser::parse_optional_header() {
    reader_.seek(info_.optional_header_offset);

    // Read magic to determine PE32 or PE32+
    auto magic = reader_.peek<std::uint16_t>();
    if (!magic) {
        return std::unexpected(parse_error("Failed to read optional header magic"));
    }

    PEMagic pe_magic = static_cast<PEMagic>(*magic);
    info_.is_pe32_plus = (pe_magic == PEMagic::PE32Plus);

    if (info_.is_pe32_plus) {
        auto opt_header = reader_.read_struct<OptionalHeader64>();
        if (!opt_header) {
            return std::unexpected(parse_error("Failed to read PE32+ optional header"));
        }

        info_.image_base = opt_header->ImageBase;
        info_.entry_point_rva = opt_header->AddressOfEntryPoint;
        info_.section_alignment = opt_header->SectionAlignment;
        info_.file_alignment = opt_header->FileAlignment;
        info_.size_of_image = opt_header->SizeOfImage;
        info_.size_of_headers = opt_header->SizeOfHeaders;
        info_.subsystem = opt_header->Subsystem_;
        info_.dll_characteristics = opt_header->DllCharacteristics_;

        // Read data directories
        std::size_t num_dirs = std::min(
            static_cast<std::size_t>(opt_header->NumberOfRvaAndSizes),
            static_cast<std::size_t>(DataDirectoryIndex::Count)
        );

        for (std::size_t i = 0; i < num_dirs; ++i) {
            auto dir = reader_.read_struct<DataDirectory>();
            if (!dir) {
                return std::unexpected(parse_error("Failed to read data directory"));
            }
            info_.data_directories[i] = *dir;
        }
    } else {
        auto opt_header = reader_.read_struct<OptionalHeader32>();
        if (!opt_header) {
            return std::unexpected(parse_error("Failed to read PE32 optional header"));
        }

        info_.image_base = opt_header->ImageBase;
        info_.entry_point_rva = opt_header->AddressOfEntryPoint;
        info_.section_alignment = opt_header->SectionAlignment;
        info_.file_alignment = opt_header->FileAlignment;
        info_.size_of_image = opt_header->SizeOfImage;
        info_.size_of_headers = opt_header->SizeOfHeaders;
        info_.subsystem = opt_header->Subsystem_;
        info_.dll_characteristics = opt_header->DllCharacteristics_;

        // Read data directories
        std::size_t num_dirs = std::min(
            static_cast<std::size_t>(opt_header->NumberOfRvaAndSizes),
            static_cast<std::size_t>(DataDirectoryIndex::Count)
        );

        for (std::size_t i = 0; i < num_dirs; ++i) {
            auto dir = reader_.read_struct<DataDirectory>();
            if (!dir) {
                return std::unexpected(parse_error("Failed to read data directory"));
            }
            info_.data_directories[i] = *dir;
        }
    }

    info_.section_headers_offset = reader_.position();
    return {};
}

Result<void> PEParser::parse_section_headers() {
    reader_.seek(info_.section_headers_offset);

    info_.sections.reserve(info_.num_sections);

    for (std::uint16_t i = 0; i < info_.num_sections; ++i) {
        auto section = reader_.read_struct<SectionHeader>();
        if (!section) {
            return std::unexpected(parse_error("Failed to read section header"));
        }
        info_.sections.push_back(*section);
    }

    return {};
}

std::optional<FileOffset> PEParser::rva_to_file_offset(RVA rva) const {
    for (const auto& section : info_.sections) {
        std::uint32_t section_start = section.VirtualAddress;
        std::uint32_t section_end = section_start + std::max(section.VirtualSize, section.SizeOfRawData);

        if (rva >= section_start && rva < section_end) {
            std::uint32_t offset_in_section = rva - section_start;
            if (offset_in_section < section.SizeOfRawData) {
                return section.PointerToRawData + offset_in_section;
            }
            return std::nullopt; // In virtual space but not in file
        }
    }

    // Check if RVA is in headers
    if (rva < info_.size_of_headers) {
        return rva;
    }

    return std::nullopt;
}

Address PEParser::rva_to_va(RVA rva) const noexcept {
    return info_.image_base + rva;
}

std::optional<RVA> PEParser::file_offset_to_rva(FileOffset offset) const {
    for (const auto& section : info_.sections) {
        FileOffset section_start = section.PointerToRawData;
        FileOffset section_end = section_start + section.SizeOfRawData;

        if (offset >= section_start && offset < section_end) {
            std::uint32_t offset_in_section = static_cast<std::uint32_t>(offset - section_start);
            return section.VirtualAddress + offset_in_section;
        }
    }

    // Check if offset is in headers
    if (offset < info_.size_of_headers) {
        return static_cast<RVA>(offset);
    }

    return std::nullopt;
}

const SectionHeader* PEParser::find_section_by_rva(RVA rva) const {
    for (const auto& section : info_.sections) {
        std::uint32_t section_start = section.VirtualAddress;
        std::uint32_t section_size = std::max(section.VirtualSize, section.SizeOfRawData);

        if (rva >= section_start && rva < section_start + section_size) {
            return &section;
        }
    }
    return nullptr;
}

const SectionHeader* PEParser::find_section_by_name(std::string_view name) const {
    for (const auto& section : info_.sections) {
        if (section.name() == name) {
            return &section;
        }
    }
    return nullptr;
}

std::optional<ByteSpan> PEParser::get_section_data(const SectionHeader& section) const {
    if (section.PointerToRawData == 0 || section.SizeOfRawData == 0) {
        return std::nullopt;
    }

    if (section.PointerToRawData + section.SizeOfRawData > data_.size()) {
        return std::nullopt;
    }

    return data_.subspan(section.PointerToRawData, section.SizeOfRawData);
}

std::optional<ByteSpan> PEParser::get_data_at_rva(RVA rva, std::size_t size) const {
    auto file_offset = rva_to_file_offset(rva);
    if (!file_offset) {
        return std::nullopt;
    }

    if (*file_offset + size > data_.size()) {
        return std::nullopt;
    }

    return data_.subspan(*file_offset, size);
}

std::optional<std::string_view> PEParser::read_string_at_rva(RVA rva) const {
    auto file_offset = rva_to_file_offset(rva);
    if (!file_offset) {
        return std::nullopt;
    }

    if (*file_offset >= data_.size()) {
        return std::nullopt;
    }

    const char* start = reinterpret_cast<const char*>(data_.data() + *file_offset);
    std::size_t max_len = data_.size() - *file_offset;

    std::size_t len = 0;
    while (len < max_len && start[len] != '\0') {
        ++len;
    }

    if (len == max_len) {
        return std::nullopt; // No null terminator
    }

    return std::string_view(start, len);
}

bool is_valid_pe(ByteSpan data) {
    if (data.size() < sizeof(DosHeader)) {
        return false;
    }

    SpanReader reader(data);

    auto dos = reader.read_struct<DosHeader>();
    if (!dos || dos->e_magic != DOS_SIGNATURE) {
        return false;
    }

    if (dos->e_lfanew < 0 || static_cast<std::size_t>(dos->e_lfanew) + 4 > data.size()) {
        return false;
    }

    reader.seek(dos->e_lfanew);
    auto pe_sig = reader.read_u32();

    return pe_sig && *pe_sig == PE_SIGNATURE;
}

std::string_view machine_type_to_string(MachineType machine) {
    switch (machine) {
        case MachineType::Unknown: return "Unknown";
        case MachineType::I386:    return "i386";
        case MachineType::AMD64:   return "AMD64";
        case MachineType::ARM:     return "ARM";
        case MachineType::ARM64:   return "ARM64";
        case MachineType::ARMNT:   return "ARMNT";
        case MachineType::IA64:    return "IA64";
        default:                   return "Unknown";
    }
}

std::string_view subsystem_to_string(Subsystem subsystem) {
    switch (subsystem) {
        case Subsystem::Unknown:                return "Unknown";
        case Subsystem::Native:                 return "Native";
        case Subsystem::WindowsGui:             return "Windows GUI";
        case Subsystem::WindowsCui:             return "Windows Console";
        case Subsystem::Os2Cui:                 return "OS/2 Console";
        case Subsystem::PosixCui:               return "POSIX Console";
        case Subsystem::NativeWindows:          return "Native Windows";
        case Subsystem::WindowsCEGui:           return "Windows CE GUI";
        case Subsystem::EfiApplication:         return "EFI Application";
        case Subsystem::EfiBootServiceDriver:   return "EFI Boot Service Driver";
        case Subsystem::EfiRuntimeDriver:       return "EFI Runtime Driver";
        case Subsystem::EfiRom:                 return "EFI ROM";
        case Subsystem::Xbox:                   return "Xbox";
        case Subsystem::WindowsBootApplication: return "Windows Boot Application";
        default:                                return "Unknown";
    }
}

} // namespace picanha::loader::pe
