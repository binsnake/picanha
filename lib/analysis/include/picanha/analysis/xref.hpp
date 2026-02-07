#pragma once

#include <picanha/core/types.hpp>
#include <cstdint>
#include <vector>

namespace picanha::analysis {

// Type of cross-reference
enum class XRefType : std::uint8_t {
    // Code references
    Call,               // Direct call
    IndirectCall,       // Call through pointer/register
    Jump,               // Unconditional jump
    ConditionalJump,    // Conditional branch
    IndirectJump,       // Jump through pointer/register (switch table, etc.)

    // Data references
    Read,               // Memory read
    Write,              // Memory write
    ReadWrite,          // Both read and write
    Offset,             // Address/offset reference (lea, etc.)

    // Special
    StringRef,          // Reference to string data
    VTableRef,          // Reference to/from vtable
    Import,             // Import reference
    Export,             // Export reference

    Unknown,
};

// Flow type for the reference
enum class XRefFlow : std::uint8_t {
    Near,       // Same segment/section
    Far,        // Different segment/section
    External,   // External module
};

// A single cross-reference
struct XRef {
    Address from;           // Source address
    Address to;             // Target address
    XRefType type;          // Type of reference
    XRefFlow flow;          // Flow type

    // Optional context
    FunctionId from_func{INVALID_FUNCTION_ID};   // Function containing 'from'
    FunctionId to_func{INVALID_FUNCTION_ID};     // Function containing 'to'
    BlockId from_block{INVALID_BLOCK_ID};        // Block containing 'from'
    BlockId to_block{INVALID_BLOCK_ID};          // Block containing 'to'

    // Flags
    bool is_user_defined{false};    // Created by user
    bool is_indirect{false};        // Indirect reference
    bool is_conditional{false};     // Conditional branch

    // Comparison for deduplication
    bool operator==(const XRef& other) const {
        return from == other.from && to == other.to && type == other.type;
    }

    bool operator<(const XRef& other) const {
        if (from != other.from) return from < other.from;
        if (to != other.to) return to < other.to;
        return static_cast<int>(type) < static_cast<int>(other.type);
    }
};

// XRef query result
struct XRefQueryResult {
    std::vector<XRef> refs_from;    // References from address
    std::vector<XRef> refs_to;      // References to address
};

// Helper functions
inline bool is_code_xref(XRefType type) {
    switch (type) {
        case XRefType::Call:
        case XRefType::IndirectCall:
        case XRefType::Jump:
        case XRefType::ConditionalJump:
        case XRefType::IndirectJump:
            return true;
        default:
            return false;
    }
}

inline bool is_data_xref(XRefType type) {
    switch (type) {
        case XRefType::Read:
        case XRefType::Write:
        case XRefType::ReadWrite:
        case XRefType::Offset:
        case XRefType::StringRef:
        case XRefType::VTableRef:
            return true;
        default:
            return false;
    }
}

inline bool is_call_xref(XRefType type) {
    return type == XRefType::Call || type == XRefType::IndirectCall;
}

inline bool is_jump_xref(XRefType type) {
    return type == XRefType::Jump ||
           type == XRefType::ConditionalJump ||
           type == XRefType::IndirectJump;
}

inline const char* xref_type_name(XRefType type) {
    switch (type) {
        case XRefType::Call: return "call";
        case XRefType::IndirectCall: return "icall";
        case XRefType::Jump: return "jmp";
        case XRefType::ConditionalJump: return "jcc";
        case XRefType::IndirectJump: return "ijmp";
        case XRefType::Read: return "read";
        case XRefType::Write: return "write";
        case XRefType::ReadWrite: return "rw";
        case XRefType::Offset: return "offset";
        case XRefType::StringRef: return "string";
        case XRefType::VTableRef: return "vtable";
        case XRefType::Import: return "import";
        case XRefType::Export: return "export";
        case XRefType::Unknown: return "unknown";
    }
    return "?";
}

} // namespace picanha::analysis
