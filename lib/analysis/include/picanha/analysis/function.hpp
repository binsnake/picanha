#pragma once

#include "picanha/analysis/cfg.hpp"
#include "picanha/analysis/basic_block.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/bitflags.hpp>
#include <string>
#include <vector>
#include <memory>

namespace picanha::analysis {

// Bring bitflag operators into this namespace for ADL
using picanha::operator|;
using picanha::operator&;
using picanha::operator^;
using picanha::operator~;
using picanha::operator|=;
using picanha::operator&=;
using picanha::operator^=;
using picanha::has_flag;

// Function calling convention
enum class CallingConvention : std::uint8_t {
    Unknown,
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Vectorcall,
    Win64,      // Microsoft x64
    SysV64,     // System V AMD64 ABI
};

// Function type
enum class FunctionType : std::uint8_t {
    Normal,
    Import,         // Imported from DLL
    Export,         // Exported
    Thunk,          // JMP to import
    RuntimeInit,    // CRT initialization
    TlsCallback,    // TLS callback
    Exception,      // Exception handler
    VirtualMethod,  // Virtual method (inferred)
};

// Function flags
enum class FunctionFlags : std::uint32_t {
    None            = 0,
    HasVarArgs      = 1 << 0,
    NoReturn        = 1 << 1,
    Naked           = 1 << 2,
    HasSEH          = 1 << 3,
    HasEHInfo       = 1 << 4,
    IsLeaf          = 1 << 5,    // No calls
    HasFramePointer = 1 << 6,
    HasStackFrame   = 1 << 7,
    IsPure          = 1 << 8,    // No side effects
    IsConst         = 1 << 9,    // Doesn't modify state
    HasLoops        = 1 << 10,
    HasIndirectCalls = 1 << 11,
    HasIndirectJumps = 1 << 12,
    IsRecursive     = 1 << 13,
    IsLibrary       = 1 << 14,   // Part of runtime library
};
PICANHA_ENABLE_BITFLAGS(FunctionFlags);

// Analyzed function
class Function {
public:
    Function() = default;
    explicit Function(FunctionId id, Address entry);

    // Identity
    [[nodiscard]] FunctionId id() const noexcept { return id_; }
    [[nodiscard]] Address entry_address() const noexcept { return entry_address_; }
    [[nodiscard]] const std::string& name() const noexcept { return name_; }

    void set_id(FunctionId id) noexcept { id_ = id; }
    void set_name(std::string name) { name_ = std::move(name); }

    // Address range (may be non-contiguous due to chunks)
    [[nodiscard]] Address start_address() const noexcept;
    [[nodiscard]] Address end_address() const noexcept;
    [[nodiscard]] Size size() const noexcept;

    // Type and convention
    [[nodiscard]] FunctionType type() const noexcept { return type_; }
    [[nodiscard]] CallingConvention calling_convention() const noexcept { return calling_conv_; }

    void set_type(FunctionType t) noexcept { type_ = t; }
    void set_calling_convention(CallingConvention cc) noexcept { calling_conv_ = cc; }

    // Flags
    [[nodiscard]] FunctionFlags flags() const noexcept { return flags_; }
    [[nodiscard]] bool has_flag(FunctionFlags f) const noexcept {
        return picanha::has_flag(flags_, f);
    }
    void set_flag(FunctionFlags f) noexcept { flags_ = flags_ | f; }
    void clear_flag(FunctionFlags f) noexcept { flags_ = flags_ & ~f; }

    // CFG
    [[nodiscard]] CFG& cfg() noexcept { return cfg_; }
    [[nodiscard]] const CFG& cfg() const noexcept { return cfg_; }
    void set_cfg(CFG cfg) { cfg_ = std::move(cfg); }

    // Block access (convenience)
    [[nodiscard]] BasicBlock* entry_block();
    [[nodiscard]] const BasicBlock* entry_block() const;
    [[nodiscard]] std::size_t block_count() const noexcept { return cfg_.block_count(); }
    [[nodiscard]] std::size_t instruction_count() const noexcept { return cfg_.instruction_count(); }

    // Callees/callers (set by analysis)
    [[nodiscard]] const std::vector<FunctionId>& callees() const noexcept { return callees_; }
    [[nodiscard]] const std::vector<FunctionId>& callers() const noexcept { return callers_; }

    void add_callee(FunctionId id) { callees_.push_back(id); }
    void add_caller(FunctionId id) { callers_.push_back(id); }

    // Stack frame
    [[nodiscard]] std::int32_t stack_frame_size() const noexcept { return stack_frame_size_; }
    [[nodiscard]] std::int32_t local_vars_size() const noexcept { return local_vars_size_; }
    [[nodiscard]] std::int32_t args_size() const noexcept { return args_size_; }

    void set_stack_frame_size(std::int32_t size) noexcept { stack_frame_size_ = size; }
    void set_local_vars_size(std::int32_t size) noexcept { local_vars_size_ = size; }
    void set_args_size(std::int32_t size) noexcept { args_size_ = size; }

    // Analysis helpers
    [[nodiscard]] bool is_thunk() const noexcept { return type_ == FunctionType::Thunk; }
    [[nodiscard]] bool is_import() const noexcept { return type_ == FunctionType::Import; }
    [[nodiscard]] bool is_export() const noexcept { return type_ == FunctionType::Export; }
    [[nodiscard]] bool is_leaf() const noexcept { return has_flag(FunctionFlags::IsLeaf); }
    [[nodiscard]] bool has_loops() const noexcept { return has_flag(FunctionFlags::HasLoops); }

private:
    FunctionId id_{INVALID_FUNCTION_ID};
    Address entry_address_{INVALID_ADDRESS};
    std::string name_;

    FunctionType type_{FunctionType::Normal};
    CallingConvention calling_conv_{CallingConvention::Unknown};
    FunctionFlags flags_{FunctionFlags::None};

    CFG cfg_;

    std::vector<FunctionId> callees_;
    std::vector<FunctionId> callers_;

    std::int32_t stack_frame_size_{0};
    std::int32_t local_vars_size_{0};
    std::int32_t args_size_{0};
};

} // namespace picanha::analysis
