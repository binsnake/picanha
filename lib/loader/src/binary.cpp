#include "picanha/loader/binary.hpp"
#include <fstream>

namespace picanha::loader {

Result<std::unique_ptr<Binary>> Binary::load_file(const std::filesystem::path& path) {
    // Read file
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return std::unexpected(io_error("Failed to open file: " + path.string()));
    }

    auto size = file.tellg();
    file.seekg(0);

    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        return std::unexpected(io_error("Failed to read file: " + path.string()));
    }

    auto result = load_memory(ByteSpan(data), path.filename().string());
    if (!result) {
        return std::unexpected(result.error());
    }

    return result;
}

Result<std::unique_ptr<Binary>> Binary::load_memory(ByteSpan data, std::string name) {
    auto binary = std::unique_ptr<Binary>(new Binary());
    binary->name_ = std::move(name);

    // Try to detect format
    if (pe::is_valid_pe(data)) {
        auto result = binary->parse_pe(data);
        if (!result) {
            return std::unexpected(result.error());
        }
        return binary;
    }

    return std::unexpected(parse_error("Unknown binary format"));
}

Result<void> Binary::parse_pe(ByteSpan data) {
    pe::PEParser parser(data);
    auto info_result = parser.parse();
    if (!info_result) {
        return std::unexpected(info_result.error());
    }

    pe_info_ = std::make_unique<pe::PEInfo>(std::move(*info_result));

    // Set format and bitness
    format_ = pe_info_->is_pe32_plus ? BinaryFormat::PE64 : BinaryFormat::PE32;
    bitness_ = pe_info_->bitness();
    entry_point_ = pe_info_->entry_point();

    // Build sections
    sections_ = pe::build_sections(*pe_info_);

    // Create memory segments
    std::vector<MemorySegment> segments;
    segments.reserve(sections_.size() + 1);

    // Add PE headers as a segment (from image_base to first section)
    Size header_size = pe_info_->size_of_headers;
    if (header_size > 0) {
        MemorySegment header_seg;
        header_seg.name = "[Headers]";
        header_seg.virtual_address = pe_info_->image_base;
        header_seg.virtual_size = header_size;
        header_seg.file_offset = 0;
        header_seg.file_size = header_size;
        header_seg.permissions = MemoryPermissions::Read;
        header_seg.section_index = static_cast<SectionIndex>(-1);
        segments.push_back(std::move(header_seg));
    }

    for (const auto& section : sections_) {
        MemorySegment seg;
        seg.name = section.name;
        seg.virtual_address = section.virtual_address;
        seg.virtual_size = section.virtual_size;
        seg.file_offset = section.file_offset;
        seg.file_size = section.file_size;
        seg.permissions = section.permissions;
        seg.section_index = section.index;
        segments.push_back(std::move(seg));
    }

    // Create memory map
    auto map_result = MemoryMap::create(
        data,
        pe_info_->image_base,
        pe_info_->size_of_image,
        std::move(segments)
    );
    if (!map_result) {
        return std::unexpected(map_result.error());
    }
    memory_map_ = std::move(*map_result);

    // Parse exports
    auto exports_result = pe::parse_exports(parser);
    if (exports_result) {
        exports_ = std::make_unique<pe::ExportInfo>(std::move(*exports_result));
    }

    // Parse imports
    auto imports_result = pe::parse_imports(parser);
    if (imports_result) {
        imports_ = std::make_unique<pe::ImportInfo>(std::move(*imports_result));
    }

    // Parse relocations
    auto relocs_result = pe::parse_relocations(parser);
    if (relocs_result) {
        relocations_ = std::make_unique<pe::RelocationInfo>(std::move(*relocs_result));
    }

    // Parse exceptions (x64 only)
    auto exceptions_result = pe::parse_exceptions(parser);
    if (exceptions_result) {
        exceptions_ = std::make_unique<pe::ExceptionInfo>(std::move(*exceptions_result));
    }

    return {};
}

const pe::Section* Binary::find_section(Address va) const {
    for (const auto& section : sections_) {
        if (section.contains_va(va)) {
            return &section;
        }
    }
    return nullptr;
}

const pe::Section* Binary::find_section_by_name(std::string_view name) const {
    for (const auto& section : sections_) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

const pe::FunctionEntry* Binary::find_function(Address va) const {
    if (!exceptions_) {
        return nullptr;
    }
    return exceptions_->find_containing(va);
}

const pe::Export* Binary::find_export(std::string_view name) const {
    if (!exports_) {
        return nullptr;
    }
    return exports_->find_by_name(name);
}

const pe::Export* Binary::find_export_at(Address va) const {
    if (!exports_ || !pe_info_) {
        return nullptr;
    }

    // Convert VA to RVA
    if (va < pe_info_->image_base) {
        return nullptr;
    }

    RVA rva = static_cast<RVA>(va - pe_info_->image_base);
    return exports_->find_by_rva(rva);
}

std::pair<const pe::ImportedModule*, const pe::ImportedFunction*>
Binary::find_import(std::string_view dll, std::string_view func) const {
    if (!imports_) {
        return {nullptr, nullptr};
    }
    return imports_->find_function(dll, func);
}

std::optional<std::string> Binary::get_symbol_name(Address va) const {
    // First check exports
    if (auto* exp = find_export_at(va)) {
        if (exp->has_name()) {
            return exp->name;
        }
        return std::format("ordinal_{}", exp->ordinal);
    }

    // Check exception directory for function start
    if (auto* func = find_function(va)) {
        if (func->begin_address == va) {
            return std::format("sub_{:x}", va);
        }
    }

    return std::nullopt;
}

} // namespace picanha::loader
