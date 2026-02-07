#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <source_location>
#include <format>

namespace picanha {

// Error category for classification
enum class ErrorCategory {
    None,
    IO,
    Parse,
    Memory,
    Analysis,
    Plugin,
    Database,
    Internal
};

// Error type with context
class Error {
public:
    Error() = default;

    explicit Error(std::string_view message,
                   ErrorCategory category = ErrorCategory::Internal,
                   std::source_location loc = std::source_location::current())
        : message_(message)
        , category_(category)
        , file_(loc.file_name())
        , line_(loc.line())
        , function_(loc.function_name())
    {}

    Error(std::string message,
          ErrorCategory category = ErrorCategory::Internal,
          std::source_location loc = std::source_location::current())
        : message_(std::move(message))
        , category_(category)
        , file_(loc.file_name())
        , line_(loc.line())
        , function_(loc.function_name())
    {}

    [[nodiscard]] std::string_view message() const noexcept { return message_; }
    [[nodiscard]] ErrorCategory category() const noexcept { return category_; }
    [[nodiscard]] std::string_view file() const noexcept { return file_; }
    [[nodiscard]] std::uint32_t line() const noexcept { return line_; }
    [[nodiscard]] std::string_view function() const noexcept { return function_; }

    [[nodiscard]] std::string format() const {
        return std::format("[{}:{}] {}: {}", file_, line_, function_, message_);
    }

    // Chain errors
    [[nodiscard]] Error with_context(std::string_view context) const {
        return Error(std::format("{}: {}", context, message_), category_);
    }

private:
    std::string message_;
    ErrorCategory category_{ErrorCategory::None};
    std::string_view file_;
    std::uint32_t line_{0};
    std::string_view function_;
};

// Result type alias using std::expected
template<typename T>
using Result = std::expected<T, Error>;

// Void result for operations that don't return a value
using VoidResult = std::expected<void, Error>;

// Helper macros for error propagation
#define PICANHA_TRY(expr) \
    ({ \
        auto&& _result = (expr); \
        if (!_result) return std::unexpected(_result.error()); \
        std::move(*_result); \
    })

#define PICANHA_TRY_VOID(expr) \
    do { \
        auto&& _result = (expr); \
        if (!_result) return std::unexpected(_result.error()); \
    } while(0)

// Convenience error constructors
inline Error io_error(std::string_view msg, std::source_location loc = std::source_location::current()) {
    return Error(msg, ErrorCategory::IO, loc);
}

inline Error parse_error(std::string_view msg, std::source_location loc = std::source_location::current()) {
    return Error(msg, ErrorCategory::Parse, loc);
}

inline Error memory_error(std::string_view msg, std::source_location loc = std::source_location::current()) {
    return Error(msg, ErrorCategory::Memory, loc);
}

inline Error analysis_error(std::string_view msg, std::source_location loc = std::source_location::current()) {
    return Error(msg, ErrorCategory::Analysis, loc);
}

inline Error plugin_error(std::string_view msg, std::source_location loc = std::source_location::current()) {
    return Error(msg, ErrorCategory::Plugin, loc);
}

inline Error database_error(std::string_view msg, std::source_location loc = std::source_location::current()) {
    return Error(msg, ErrorCategory::Database, loc);
}

inline Error internal_error(std::string_view msg, std::source_location loc = std::source_location::current()) {
    return Error(msg, ErrorCategory::Internal, loc);
}

} // namespace picanha
