#pragma once

#include <span>
#include <cstdint>
#include <cstring>
#include <optional>
#include <type_traits>
#include <string_view>

namespace picanha {

// Byte span alias
using ByteSpan = std::span<const std::uint8_t>;
using MutableByteSpan = std::span<std::uint8_t>;

// Safe memory reader for binary data
class SpanReader {
public:
    explicit SpanReader(ByteSpan data) noexcept
        : data_(data), pos_(0) {}

    SpanReader(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data, size), pos_(0) {}

    // Position management
    [[nodiscard]] std::size_t position() const noexcept { return pos_; }
    [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - pos_; }
    [[nodiscard]] bool eof() const noexcept { return pos_ >= data_.size(); }
    [[nodiscard]] ByteSpan data() const noexcept { return data_; }

    void seek(std::size_t pos) noexcept {
        pos_ = std::min(pos, data_.size());
    }

    void skip(std::size_t count) noexcept {
        pos_ = std::min(pos_ + count, data_.size());
    }

    // Read primitives (little-endian)
    template<typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] std::optional<T> read() noexcept {
        if (pos_ + sizeof(T) > data_.size()) {
            return std::nullopt;
        }
        T value;
        std::memcpy(&value, data_.data() + pos_, sizeof(T));
        pos_ += sizeof(T);
        return value;
    }

    [[nodiscard]] std::optional<std::uint8_t> read_u8() noexcept { return read<std::uint8_t>(); }
    [[nodiscard]] std::optional<std::uint16_t> read_u16() noexcept { return read<std::uint16_t>(); }
    [[nodiscard]] std::optional<std::uint32_t> read_u32() noexcept { return read<std::uint32_t>(); }
    [[nodiscard]] std::optional<std::uint64_t> read_u64() noexcept { return read<std::uint64_t>(); }

    [[nodiscard]] std::optional<std::int8_t> read_i8() noexcept { return read<std::int8_t>(); }
    [[nodiscard]] std::optional<std::int16_t> read_i16() noexcept { return read<std::int16_t>(); }
    [[nodiscard]] std::optional<std::int32_t> read_i32() noexcept { return read<std::int32_t>(); }
    [[nodiscard]] std::optional<std::int64_t> read_i64() noexcept { return read<std::int64_t>(); }

    // Read a struct
    template<typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] std::optional<T> read_struct() noexcept {
        return read<T>();
    }

    // Peek without advancing
    template<typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] std::optional<T> peek() const noexcept {
        if (pos_ + sizeof(T) > data_.size()) {
            return std::nullopt;
        }
        T value;
        std::memcpy(&value, data_.data() + pos_, sizeof(T));
        return value;
    }

    // Read bytes into a span
    [[nodiscard]] std::optional<ByteSpan> read_bytes(std::size_t count) noexcept {
        if (pos_ + count > data_.size()) {
            return std::nullopt;
        }
        auto span = data_.subspan(pos_, count);
        pos_ += count;
        return span;
    }

    // Get a subspan from current position
    [[nodiscard]] ByteSpan remaining_span() const noexcept {
        return data_.subspan(pos_);
    }

    // Read null-terminated string
    [[nodiscard]] std::optional<std::string_view> read_cstring() noexcept {
        const char* start = reinterpret_cast<const char*>(data_.data() + pos_);
        std::size_t max_len = remaining();

        std::size_t len = 0;
        while (len < max_len && start[len] != '\0') {
            ++len;
        }

        if (len == max_len) {
            return std::nullopt; // No null terminator found
        }

        pos_ += len + 1; // Include null terminator
        return std::string_view(start, len);
    }

    // Read fixed-length string (may not be null-terminated)
    [[nodiscard]] std::optional<std::string_view> read_string(std::size_t length) noexcept {
        if (pos_ + length > data_.size()) {
            return std::nullopt;
        }

        const char* start = reinterpret_cast<const char*>(data_.data() + pos_);
        pos_ += length;

        // Find actual length (stop at null)
        std::size_t actual_len = 0;
        while (actual_len < length && start[actual_len] != '\0') {
            ++actual_len;
        }

        return std::string_view(start, actual_len);
    }

    // Read at a specific offset without changing position
    template<typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] std::optional<T> read_at(std::size_t offset) const noexcept {
        if (offset + sizeof(T) > data_.size()) {
            return std::nullopt;
        }
        T value;
        std::memcpy(&value, data_.data() + offset, sizeof(T));
        return value;
    }

private:
    ByteSpan data_;
    std::size_t pos_;
};

// Helper to create a span from a container
template<typename Container>
[[nodiscard]] ByteSpan as_bytes(const Container& c) noexcept {
    return ByteSpan(reinterpret_cast<const std::uint8_t*>(c.data()), c.size() * sizeof(typename Container::value_type));
}

// Helper to create a span from a single value
template<typename T>
    requires std::is_trivially_copyable_v<T>
[[nodiscard]] ByteSpan as_bytes(const T& value) noexcept {
    return ByteSpan(reinterpret_cast<const std::uint8_t*>(&value), sizeof(T));
}

} // namespace picanha
