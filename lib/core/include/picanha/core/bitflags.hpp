#pragma once

#include <type_traits>
#include <cstdint>

namespace picanha {

// Enable bitwise operators for enum class types
// Usage: template<> struct EnableBitflags<MyEnum> : std::true_type {};
template<typename T>
struct EnableBitflags : std::false_type {};

template<typename T>
concept Bitflag = std::is_enum_v<T> && EnableBitflags<T>::value;

// Bitwise operators for bitflag enums
template<Bitflag T>
[[nodiscard]] constexpr T operator|(T lhs, T rhs) noexcept {
    using U = std::underlying_type_t<T>;
    return static_cast<T>(static_cast<U>(lhs) | static_cast<U>(rhs));
}

template<Bitflag T>
[[nodiscard]] constexpr T operator&(T lhs, T rhs) noexcept {
    using U = std::underlying_type_t<T>;
    return static_cast<T>(static_cast<U>(lhs) & static_cast<U>(rhs));
}

template<Bitflag T>
[[nodiscard]] constexpr T operator^(T lhs, T rhs) noexcept {
    using U = std::underlying_type_t<T>;
    return static_cast<T>(static_cast<U>(lhs) ^ static_cast<U>(rhs));
}

template<Bitflag T>
[[nodiscard]] constexpr T operator~(T val) noexcept {
    using U = std::underlying_type_t<T>;
    return static_cast<T>(~static_cast<U>(val));
}

template<Bitflag T>
constexpr T& operator|=(T& lhs, T rhs) noexcept {
    return lhs = lhs | rhs;
}

template<Bitflag T>
constexpr T& operator&=(T& lhs, T rhs) noexcept {
    return lhs = lhs & rhs;
}

template<Bitflag T>
constexpr T& operator^=(T& lhs, T rhs) noexcept {
    return lhs = lhs ^ rhs;
}

// Check if a flag is set
template<Bitflag T>
[[nodiscard]] constexpr bool has_flag(T value, T flag) noexcept {
    using U = std::underlying_type_t<T>;
    return (static_cast<U>(value) & static_cast<U>(flag)) == static_cast<U>(flag);
}

// Check if any flags are set
template<Bitflag T>
[[nodiscard]] constexpr bool has_any_flag(T value, T flags) noexcept {
    using U = std::underlying_type_t<T>;
    return (static_cast<U>(value) & static_cast<U>(flags)) != 0;
}

// Check if no flags are set (value is zero)
template<Bitflag T>
[[nodiscard]] constexpr bool is_empty(T value) noexcept {
    using U = std::underlying_type_t<T>;
    return static_cast<U>(value) == 0;
}

// Set a flag
template<Bitflag T>
constexpr void set_flag(T& value, T flag) noexcept {
    value |= flag;
}

// Clear a flag
template<Bitflag T>
constexpr void clear_flag(T& value, T flag) noexcept {
    value &= ~flag;
}

// Toggle a flag
template<Bitflag T>
constexpr void toggle_flag(T& value, T flag) noexcept {
    value ^= flag;
}

// Set or clear a flag based on condition
template<Bitflag T>
constexpr void set_flag_if(T& value, T flag, bool condition) noexcept {
    if (condition) {
        set_flag(value, flag);
    } else {
        clear_flag(value, flag);
    }
}

// Convert to underlying type
template<Bitflag T>
[[nodiscard]] constexpr auto to_underlying(T value) noexcept {
    return static_cast<std::underlying_type_t<T>>(value);
}

// Macro to enable bitflags for an enum
#define PICANHA_ENABLE_BITFLAGS(EnumType) \
    template<> struct ::picanha::EnableBitflags<EnumType> : std::true_type {}

} // namespace picanha
