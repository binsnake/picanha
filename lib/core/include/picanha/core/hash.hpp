#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <memory>

// XXH_STATIC_LINKING_ONLY exposes internal types needed for StreamingHasher
// Don't define XXH_IMPLEMENTATION - use vcpkg library for implementation
#define XXH_STATIC_LINKING_ONLY
#include <xxhash.h>

namespace picanha {

// Fast hashing using xxHash
class Hash {
public:
    // Hash bytes
    [[nodiscard]] static std::uint64_t hash64(const void* data, std::size_t len) noexcept {
        return XXH3_64bits(data, len);
    }

    [[nodiscard]] static std::uint64_t hash64(std::span<const std::uint8_t> data) noexcept {
        return XXH3_64bits(data.data(), data.size());
    }

    [[nodiscard]] static std::uint64_t hash64(std::string_view str) noexcept {
        return XXH3_64bits(str.data(), str.size());
    }

    // 128-bit hash for stronger collision resistance
    struct Hash128 {
        std::uint64_t low;
        std::uint64_t high;

        bool operator==(const Hash128&) const = default;
    };

    [[nodiscard]] static Hash128 hash128(const void* data, std::size_t len) noexcept {
        auto result = XXH3_128bits(data, len);
        return {result.low64, result.high64};
    }

    [[nodiscard]] static Hash128 hash128(std::span<const std::uint8_t> data) noexcept {
        return hash128(data.data(), data.size());
    }

    // Combine multiple hashes (for composite keys)
    [[nodiscard]] static std::uint64_t combine(std::uint64_t a, std::uint64_t b) noexcept {
        // FNV-1a style combination
        constexpr std::uint64_t prime = 0x100000001b3;
        return (a ^ b) * prime;
    }

    template<typename... Args>
    [[nodiscard]] static std::uint64_t combine_all(std::uint64_t first, Args... args) noexcept {
        std::uint64_t result = first;
        ((result = combine(result, args)), ...);
        return result;
    }
};

// Incremental hasher for streaming data
class StreamingHasher {
public:
    StreamingHasher() noexcept {
        XXH3_64bits_reset(&state_);
    }

    void update(const void* data, std::size_t len) noexcept {
        XXH3_64bits_update(&state_, data, len);
    }

    void update(std::span<const std::uint8_t> data) noexcept {
        XXH3_64bits_update(&state_, data.data(), data.size());
    }

    void update(std::string_view str) noexcept {
        XXH3_64bits_update(&state_, str.data(), str.size());
    }

    [[nodiscard]] std::uint64_t finalize() noexcept {
        return XXH3_64bits_digest(&state_);
    }

    void reset() noexcept {
        XXH3_64bits_reset(&state_);
    }

private:
    XXH3_state_t state_;
};

// Hash functor for use with std containers
struct AddressHash {
    [[nodiscard]] std::size_t operator()(std::uint64_t addr) const noexcept {
        // Simple but fast hash for addresses
        return static_cast<std::size_t>(addr ^ (addr >> 32));
    }
};

// String hash for use with heterogeneous lookup
struct StringHash {
    using is_transparent = void;

    [[nodiscard]] std::size_t operator()(std::string_view str) const noexcept {
        return static_cast<std::size_t>(Hash::hash64(str));
    }

    [[nodiscard]] std::size_t operator()(const std::string& str) const noexcept {
        return static_cast<std::size_t>(Hash::hash64(str));
    }

    [[nodiscard]] std::size_t operator()(const char* str) const noexcept {
        return static_cast<std::size_t>(Hash::hash64(std::string_view(str)));
    }
};

} // namespace picanha
