#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/span.hpp>
#include <picanha/core/result.hpp>
#include <vector>
#include <memory>
#include <string>
#include <optional>

namespace picanha::loader {

// A memory segment (maps to a loaded section)
struct MemorySegment {
    std::string name;
    Address virtual_address;
    Size virtual_size;
    FileOffset file_offset;
    Size file_size;
    MemoryPermissions permissions;
    SectionIndex section_index;

    [[nodiscard]] AddressRange address_range() const noexcept {
        return {virtual_address, virtual_address + virtual_size};
    }

    [[nodiscard]] bool contains(Address addr) const noexcept {
        return addr >= virtual_address && addr < virtual_address + virtual_size;
    }

    [[nodiscard]] bool is_executable() const noexcept {
        return has_permission(permissions, MemoryPermissions::Execute);
    }

    [[nodiscard]] bool is_writable() const noexcept {
        return has_permission(permissions, MemoryPermissions::Write);
    }
};

// Virtual memory map - simulates the loaded binary in memory
class MemoryMap {
public:
    MemoryMap() = default;

    // Create memory map from raw file data and segment info
    static Result<MemoryMap> create(ByteSpan file_data,
                                     Address image_base,
                                     Size image_size,
                                     std::vector<MemorySegment> segments);

    // Address translation
    [[nodiscard]] std::optional<FileOffset> va_to_file_offset(Address va) const;
    [[nodiscard]] std::optional<Address> file_offset_to_va(FileOffset offset) const;

    // Read data at virtual address
    [[nodiscard]] std::optional<ByteSpan> read(Address va, Size size) const;

    // Read a value at virtual address
    template<typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] std::optional<T> read_value(Address va) const {
        auto span = read(va, sizeof(T));
        if (!span) return std::nullopt;

        T value;
        std::memcpy(&value, span->data(), sizeof(T));
        return value;
    }

    // Read null-terminated string
    [[nodiscard]] std::optional<std::string_view> read_string(Address va, Size max_len = 4096) const;

    // Find segment containing address
    [[nodiscard]] const MemorySegment* find_segment(Address va) const;

    // Find segment by name
    [[nodiscard]] const MemorySegment* find_segment_by_name(std::string_view name) const;

    // Get executable segments
    [[nodiscard]] std::vector<const MemorySegment*> executable_segments() const;

    // Check if address is valid
    [[nodiscard]] bool is_valid_address(Address va) const;

    // Check if address is executable
    [[nodiscard]] bool is_executable(Address va) const;

    // Properties
    [[nodiscard]] Address image_base() const noexcept { return image_base_; }
    [[nodiscard]] Size image_size() const noexcept { return image_size_; }
    [[nodiscard]] const std::vector<MemorySegment>& segments() const noexcept { return segments_; }
    [[nodiscard]] ByteSpan raw_data() const noexcept { return file_data_; }

    // Address range
    [[nodiscard]] AddressRange address_range() const noexcept {
        return {image_base_, image_base_ + image_size_};
    }

private:
    std::vector<std::uint8_t> file_data_storage_;  // Owned copy of file data
    ByteSpan file_data_;
    Address image_base_{0};
    Size image_size_{0};
    std::vector<MemorySegment> segments_;
};

} // namespace picanha::loader
