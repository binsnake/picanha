#pragma once

#include <cstdint>
#include <cstddef>
#include <limits>
#include <compare>

namespace picanha {

// Basic address type for virtual addresses
using Address = std::uint64_t;
using RVA = std::uint32_t;  // Relative Virtual Address (PE)
using FileOffset = std::uint64_t;

// Size types
using Size = std::uint64_t;
using Size32 = std::uint32_t;

// Invalid address sentinel
inline constexpr Address INVALID_ADDRESS = std::numeric_limits<Address>::max();
inline constexpr RVA INVALID_RVA = std::numeric_limits<RVA>::max();

// Address range
struct AddressRange {
    Address start{INVALID_ADDRESS};
    Address end{INVALID_ADDRESS};

    [[nodiscard]] constexpr bool valid() const noexcept {
        return start != INVALID_ADDRESS && end != INVALID_ADDRESS && start <= end;
    }

    [[nodiscard]] constexpr Size size() const noexcept {
        return valid() ? (end - start) : 0;
    }

    [[nodiscard]] constexpr bool contains(Address addr) const noexcept {
        return valid() && addr >= start && addr < end;
    }

    [[nodiscard]] constexpr bool overlaps(const AddressRange& other) const noexcept {
        return valid() && other.valid() && start < other.end && other.start < end;
    }

    [[nodiscard]] constexpr bool adjacent_to(const AddressRange& other) const noexcept {
        return valid() && other.valid() && (end == other.start || other.end == start);
    }

    constexpr auto operator<=>(const AddressRange&) const = default;
};

// Section index
using SectionIndex = std::uint16_t;
inline constexpr SectionIndex INVALID_SECTION = std::numeric_limits<SectionIndex>::max();

// Instruction index within a function/block
using InstructionIndex = std::uint32_t;
inline constexpr InstructionIndex INVALID_INSTRUCTION_INDEX = std::numeric_limits<InstructionIndex>::max();

// Block/function IDs for graph operations
using BlockId = std::uint32_t;
using FunctionId = std::uint32_t;
inline constexpr BlockId INVALID_BLOCK_ID = std::numeric_limits<BlockId>::max();
inline constexpr FunctionId INVALID_FUNCTION_ID = std::numeric_limits<FunctionId>::max();

// Bitness enumeration
enum class Bitness : std::uint8_t {
    Bits16 = 16,
    Bits32 = 32,
    Bits64 = 64
};

// Access permissions
enum class MemoryPermissions : std::uint8_t {
    None    = 0,
    Read    = 1 << 0,
    Write   = 1 << 1,
    Execute = 1 << 2,

    ReadWrite = Read | Write,
    ReadExecute = Read | Execute,
    ReadWriteExecute = Read | Write | Execute
};

[[nodiscard]] constexpr MemoryPermissions operator|(MemoryPermissions a, MemoryPermissions b) noexcept {
    return static_cast<MemoryPermissions>(
        static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b)
    );
}

[[nodiscard]] constexpr MemoryPermissions operator&(MemoryPermissions a, MemoryPermissions b) noexcept {
    return static_cast<MemoryPermissions>(
        static_cast<std::uint8_t>(a) & static_cast<std::uint8_t>(b)
    );
}

[[nodiscard]] constexpr bool has_permission(MemoryPermissions perms, MemoryPermissions check) noexcept {
    return (perms & check) == check;
}

} // namespace picanha
