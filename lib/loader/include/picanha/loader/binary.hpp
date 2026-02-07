#pragma once

#include "picanha/loader/memory_map.hpp"
#include "picanha/loader/pe/pe_parser.hpp"
#include "picanha/loader/pe/pe_sections.hpp"
#include "picanha/loader/pe/pe_exports.hpp"
#include "picanha/loader/pe/pe_imports.hpp"
#include "picanha/loader/pe/pe_relocations.hpp"
#include "picanha/loader/pe/pe_exceptions.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/result.hpp>
#include <filesystem>
#include <memory>
#include <string>

namespace picanha::loader {

// Binary format
enum class BinaryFormat {
    Unknown,
    PE32,       // 32-bit PE
    PE64,       // 64-bit PE (PE32+)
};

// Loaded binary with all parsed information
class Binary {
public:
    // Load from file
    static Result<std::unique_ptr<Binary>> load_file(const std::filesystem::path& path);

    // Load from memory
    static Result<std::unique_ptr<Binary>> load_memory(ByteSpan data, std::string name = "");

    // Basic info
    [[nodiscard]] const std::string& name() const noexcept { return name_; }
    [[nodiscard]] BinaryFormat format() const noexcept { return format_; }
    [[nodiscard]] Bitness bitness() const noexcept { return bitness_; }
    [[nodiscard]] bool is_64bit() const noexcept { return bitness_ == Bitness::Bits64; }

    // Addresses
    [[nodiscard]] Address image_base() const noexcept { return memory_map_.image_base(); }
    [[nodiscard]] Address entry_point() const noexcept { return entry_point_; }
    [[nodiscard]] AddressRange address_range() const noexcept { return memory_map_.address_range(); }

    // Memory access
    [[nodiscard]] const MemoryMap& memory() const noexcept { return memory_map_; }
    [[nodiscard]] std::optional<ByteSpan> read(Address va, Size size) const {
        return memory_map_.read(va, size);
    }

    // PE-specific (returns nullptr for non-PE)
    [[nodiscard]] const pe::PEInfo* pe_info() const noexcept { return pe_info_.get(); }
    [[nodiscard]] const pe::ExportInfo* exports() const noexcept { return exports_.get(); }
    [[nodiscard]] const pe::ImportInfo* imports() const noexcept { return imports_.get(); }
    [[nodiscard]] const pe::RelocationInfo* relocations() const noexcept { return relocations_.get(); }
    [[nodiscard]] const pe::ExceptionInfo* exceptions() const noexcept { return exceptions_.get(); }

    // Sections
    [[nodiscard]] const std::vector<pe::Section>& sections() const noexcept { return sections_; }
    [[nodiscard]] const pe::Section* find_section(Address va) const;
    [[nodiscard]] const pe::Section* find_section_by_name(std::string_view name) const;

    // Function lookup (from exception directory on x64)
    [[nodiscard]] const pe::FunctionEntry* find_function(Address va) const;

    // Export lookup
    [[nodiscard]] const pe::Export* find_export(std::string_view name) const;
    [[nodiscard]] const pe::Export* find_export_at(Address va) const;

    // Import lookup
    [[nodiscard]] std::pair<const pe::ImportedModule*, const pe::ImportedFunction*>
        find_import(std::string_view dll, std::string_view func) const;

    // Symbol resolution (exports, then exception directory functions)
    [[nodiscard]] std::optional<std::string> get_symbol_name(Address va) const;

private:
    Binary() = default;

    Result<void> parse_pe(ByteSpan data);

    std::string name_;
    BinaryFormat format_{BinaryFormat::Unknown};
    Bitness bitness_{Bitness::Bits64};
    Address entry_point_{0};

    MemoryMap memory_map_;

    // PE-specific
    std::unique_ptr<pe::PEInfo> pe_info_;
    std::unique_ptr<pe::ExportInfo> exports_;
    std::unique_ptr<pe::ImportInfo> imports_;
    std::unique_ptr<pe::RelocationInfo> relocations_;
    std::unique_ptr<pe::ExceptionInfo> exceptions_;
    std::vector<pe::Section> sections_;
};

} // namespace picanha::loader
