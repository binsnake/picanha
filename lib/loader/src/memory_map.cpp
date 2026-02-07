#include "picanha/loader/memory_map.hpp"
#include <algorithm>
#include <cstring>

namespace picanha::loader {

Result<MemoryMap> MemoryMap::create(ByteSpan file_data,
                                     Address image_base,
                                     Size image_size,
                                     std::vector<MemorySegment> segments) {
    MemoryMap map;

    // Copy file data
    map.file_data_storage_.assign(file_data.begin(), file_data.end());
    map.file_data_ = ByteSpan(map.file_data_storage_);
    map.image_base_ = image_base;
    map.image_size_ = image_size;
    map.segments_ = std::move(segments);

    // Sort segments by virtual address for binary search
    std::sort(map.segments_.begin(), map.segments_.end(),
        [](const MemorySegment& a, const MemorySegment& b) {
            return a.virtual_address < b.virtual_address;
        });

    return map;
}

std::optional<FileOffset> MemoryMap::va_to_file_offset(Address va) const {
    const auto* segment = find_segment(va);
    if (!segment) {
        return std::nullopt;
    }

    Size offset_in_segment = va - segment->virtual_address;
    if (offset_in_segment >= segment->file_size) {
        return std::nullopt; // In virtual space but not backed by file
    }

    return segment->file_offset + offset_in_segment;
}

std::optional<Address> MemoryMap::file_offset_to_va(FileOffset offset) const {
    for (const auto& segment : segments_) {
        if (offset >= segment.file_offset &&
            offset < segment.file_offset + segment.file_size) {
            Size offset_in_segment = offset - segment.file_offset;
            return segment.virtual_address + offset_in_segment;
        }
    }
    return std::nullopt;
}

std::optional<ByteSpan> MemoryMap::read(Address va, Size size) const {
    auto file_offset = va_to_file_offset(va);
    if (!file_offset) {
        return std::nullopt;
    }

    if (*file_offset + size > file_data_.size()) {
        return std::nullopt;
    }

    return file_data_.subspan(*file_offset, size);
}

std::optional<std::string_view> MemoryMap::read_string(Address va, Size max_len) const {
    auto file_offset = va_to_file_offset(va);
    if (!file_offset || *file_offset >= file_data_.size()) {
        return std::nullopt;
    }

    const char* start = reinterpret_cast<const char*>(file_data_.data() + *file_offset);
    Size available = file_data_.size() - *file_offset;
    Size search_len = std::min(max_len, available);

    Size len = 0;
    while (len < search_len && start[len] != '\0') {
        ++len;
    }

    if (len == search_len && start[len] != '\0') {
        return std::nullopt; // No null terminator found
    }

    return std::string_view(start, len);
}

const MemorySegment* MemoryMap::find_segment(Address va) const {
    // Binary search since segments are sorted
    auto it = std::lower_bound(segments_.begin(), segments_.end(), va,
        [](const MemorySegment& seg, Address addr) {
            return seg.virtual_address + seg.virtual_size <= addr;
        });

    if (it != segments_.end() && it->contains(va)) {
        return &(*it);
    }
    return nullptr;
}

const MemorySegment* MemoryMap::find_segment_by_name(std::string_view name) const {
    for (const auto& segment : segments_) {
        if (segment.name == name) {
            return &segment;
        }
    }
    return nullptr;
}

std::vector<const MemorySegment*> MemoryMap::executable_segments() const {
    std::vector<const MemorySegment*> result;
    for (const auto& segment : segments_) {
        if (segment.is_executable()) {
            result.push_back(&segment);
        }
    }
    return result;
}

bool MemoryMap::is_valid_address(Address va) const {
    return find_segment(va) != nullptr;
}

bool MemoryMap::is_executable(Address va) const {
    const auto* segment = find_segment(va);
    return segment && segment->is_executable();
}

} // namespace picanha::loader
