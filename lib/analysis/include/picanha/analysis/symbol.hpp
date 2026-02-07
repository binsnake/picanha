#pragma once

#include <picanha/core/types.hpp>
#include <cstdint>
#include <string>
#include <optional>

namespace picanha::analysis {

// Symbol type
enum class SymbolType : std::uint8_t {
    Unknown,
    Function,       // Code function
    Data,           // Data variable
    Label,          // Code label (within function)
    Import,         // Imported symbol
    Export,         // Exported symbol
    String,         // String data
    VTable,         // Virtual table
    TypeInfo,       // RTTI type info
    Exception,      // Exception handling data
    TLS,            // Thread-local storage
    Section,        // Section name
    Segment,        // Segment name
};

// Symbol visibility
enum class SymbolVisibility : std::uint8_t {
    Local,          // Internal linkage
    Global,         // External linkage
    Weak,           // Weak symbol
    Hidden,         // Hidden (not exported)
};

// Symbol source
enum class SymbolSource : std::uint8_t {
    Auto,           // Auto-generated
    Export,         // From export table
    Import,         // From import table
    Debug,          // From debug info/PDB
    User,           // User-defined
    Analysis,       // From analysis (e.g., string detection)
};

// Symbol flags
enum class SymbolFlags : std::uint32_t {
    None            = 0,
    IsThunk         = 1 << 0,   // Jump thunk
    IsStub          = 1 << 1,   // Stub function
    IsInline        = 1 << 2,   // Inlined function
    IsNoReturn      = 1 << 3,   // No-return function
    IsVirtual       = 1 << 4,   // Virtual method
    IsStatic        = 1 << 5,   // Static symbol
    IsConst         = 1 << 6,   // Const data
    HasTypeInfo     = 1 << 7,   // Has type information
    IsDemangled     = 1 << 8,   // Name is demangled
    IsMangled       = 1 << 9,   // Name is mangled
    IsLibrary       = 1 << 10,  // Part of runtime library
    IsGenerated     = 1 << 11,  // Compiler-generated
    IsPadding       = 1 << 12,  // Alignment padding
    UserDefined     = 1 << 13,  // User-created symbol
};

// Enable bitflags operations
inline SymbolFlags operator|(SymbolFlags a, SymbolFlags b) {
    return static_cast<SymbolFlags>(
        static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b)
    );
}

inline SymbolFlags operator&(SymbolFlags a, SymbolFlags b) {
    return static_cast<SymbolFlags>(
        static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b)
    );
}

inline SymbolFlags operator~(SymbolFlags a) {
    return static_cast<SymbolFlags>(~static_cast<std::uint32_t>(a));
}

inline bool has_flag(SymbolFlags flags, SymbolFlags flag) {
    return (static_cast<std::uint32_t>(flags) & static_cast<std::uint32_t>(flag)) != 0;
}

// Unique symbol identifier
using SymbolId = std::uint32_t;
constexpr SymbolId INVALID_SYMBOL_ID = static_cast<SymbolId>(-1);

// A symbol in the binary
struct Symbol {
    SymbolId id{INVALID_SYMBOL_ID};
    Address address{INVALID_ADDRESS};
    Size size{0};

    std::string name;
    std::string demangled_name;     // If available
    std::string module_name;        // For imports: DLL name

    SymbolType type{SymbolType::Unknown};
    SymbolVisibility visibility{SymbolVisibility::Local};
    SymbolSource source{SymbolSource::Auto};
    SymbolFlags flags{SymbolFlags::None};

    // Optional linkage to other entities
    FunctionId function_id{INVALID_FUNCTION_ID};
    std::uint16_t ordinal{0};       // For exports/imports

    // Helpers
    [[nodiscard]] bool is_function() const {
        return type == SymbolType::Function ||
               type == SymbolType::Import ||
               type == SymbolType::Export;
    }

    [[nodiscard]] bool is_data() const {
        return type == SymbolType::Data ||
               type == SymbolType::String ||
               type == SymbolType::VTable ||
               type == SymbolType::TypeInfo;
    }

    [[nodiscard]] bool is_code() const {
        return type == SymbolType::Function ||
               type == SymbolType::Label;
    }

    [[nodiscard]] bool is_import() const {
        return type == SymbolType::Import;
    }

    [[nodiscard]] bool is_export() const {
        return type == SymbolType::Export;
    }

    [[nodiscard]] bool has_flag(SymbolFlags f) const {
        return analysis::has_flag(flags, f);
    }

    [[nodiscard]] const std::string& display_name() const {
        return demangled_name.empty() ? name : demangled_name;
    }

    // For sorting
    bool operator<(const Symbol& other) const {
        return address < other.address;
    }
};

// Helper to get symbol type name
inline const char* symbol_type_name(SymbolType type) {
    switch (type) {
        case SymbolType::Unknown: return "unknown";
        case SymbolType::Function: return "function";
        case SymbolType::Data: return "data";
        case SymbolType::Label: return "label";
        case SymbolType::Import: return "import";
        case SymbolType::Export: return "export";
        case SymbolType::String: return "string";
        case SymbolType::VTable: return "vtable";
        case SymbolType::TypeInfo: return "typeinfo";
        case SymbolType::Exception: return "exception";
        case SymbolType::TLS: return "tls";
        case SymbolType::Section: return "section";
        case SymbolType::Segment: return "segment";
    }
    return "?";
}

} // namespace picanha::analysis
