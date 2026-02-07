#pragma once

#include "picanha/analysis/dag.hpp"
#include "picanha/analysis/pattern_matcher.hpp"
#include "picanha/analysis/cfg.hpp"
#include "picanha/analysis/xref.hpp"
#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>
#include <memory>
#include <vector>
#include <unordered_map>
#include <unordered_set>

namespace picanha::analysis {

// Type of indirect call
enum class IndirectCallType : std::uint8_t {
    Unknown,
    VTableCall,         // Call through vtable: call [obj + vtable_offset]
    FunctionPointer,    // Call through function pointer variable
    ImportCall,         // Call through IAT: call [__imp_func]
    RegisterCall,       // Call through register: call rax
    ComputedCall,       // Computed target
    Thunk,              // Call through thunk (jmp to real function)
};

// Information about a resolved indirect call
struct IndirectCallInfo {
    Address call_address{INVALID_ADDRESS};      // Address of call instruction
    IndirectCallType type{IndirectCallType::Unknown};

    // Possible targets
    std::vector<Address> targets;

    // For vtable calls
    Address vtable_address{INVALID_ADDRESS};
    std::int32_t vtable_offset{0};

    // For import calls
    std::string import_name;
    std::string import_module;

    // Confidence
    std::uint8_t confidence{0};

    [[nodiscard]] bool has_targets() const noexcept {
        return !targets.empty();
    }

    [[nodiscard]] bool is_single_target() const noexcept {
        return targets.size() == 1;
    }
};

// VTable information
struct VTableInfo {
    Address address{INVALID_ADDRESS};
    std::vector<Address> entries;
    std::string class_name;             // If RTTI available
    Address type_info{INVALID_ADDRESS}; // RTTI type_info pointer

    [[nodiscard]] std::size_t size() const noexcept {
        return entries.size();
    }

    [[nodiscard]] Address entry_at(std::size_t index) const {
        return index < entries.size() ? entries[index] : INVALID_ADDRESS;
    }
};

// Configuration for indirect call resolution
struct IndirectResolverConfig {
    bool resolve_vtables{true};
    bool resolve_imports{true};
    bool resolve_function_pointers{true};
    bool track_register_flow{true};
    std::size_t max_vtable_size{256};
    std::size_t backtrack_limit{50};    // Instructions to look back
};

// Indirect call resolver
class IndirectCallResolver {
public:
    IndirectCallResolver(
        std::shared_ptr<loader::Binary> binary,
        const IndirectResolverConfig& config = {}
    );

    // Analyze a single indirect call
    [[nodiscard]] IndirectCallInfo analyze_call(
        const BasicBlock& block,
        Address call_address
    );

    // Analyze all indirect calls in a function
    [[nodiscard]] std::vector<IndirectCallInfo> analyze_function(const CFG& cfg);

    // Get all discovered vtables
    [[nodiscard]] const std::vector<VTableInfo>& vtables() const noexcept {
        return vtables_;
    }

    // Find vtable at address
    [[nodiscard]] const VTableInfo* find_vtable(Address addr) const;

    // Check if address is an import thunk
    [[nodiscard]] bool is_import_call(Address call_target) const;

    // Resolve import call target
    [[nodiscard]] std::optional<std::pair<std::string, std::string>>
    resolve_import(Address iat_entry) const;

private:
    // Analyze vtable call pattern
    [[nodiscard]] IndirectCallInfo analyze_vtable_call(
        const std::vector<Instruction>& instructions,
        std::size_t call_index
    );

    // Analyze import call
    [[nodiscard]] IndirectCallInfo analyze_import_call(
        Address call_address,
        Address target_address
    );

    // Analyze register-based call
    [[nodiscard]] IndirectCallInfo analyze_register_call(
        const std::vector<Instruction>& instructions,
        std::size_t call_index,
        iced_x86::Register reg
    );

    // Discover vtable at address
    [[nodiscard]] std::optional<VTableInfo> discover_vtable(Address addr);

    // Build IAT mapping
    void build_iat_map();

    std::shared_ptr<loader::Binary> binary_;
    IndirectResolverConfig config_;
    PatternMatcher matcher_;

    std::vector<VTableInfo> vtables_;
    std::unordered_map<Address, std::size_t> vtable_map_;  // Address -> index

    // IAT mapping
    std::unordered_map<Address, std::pair<std::string, std::string>> iat_map_;
    bool iat_built_{false};
};

// VTable analyzer - discovers vtables in the binary
class VTableAnalyzer {
public:
    explicit VTableAnalyzer(std::shared_ptr<loader::Binary> binary);

    // Find all vtables
    [[nodiscard]] std::vector<VTableInfo> find_vtables();

    // Check if address looks like a vtable
    [[nodiscard]] bool is_possible_vtable(Address addr) const;

    // Read vtable entries
    [[nodiscard]] std::vector<Address> read_vtable(Address addr, std::size_t max_entries = 256);

    // Try to find RTTI for vtable
    [[nodiscard]] std::optional<std::string> find_class_name(Address vtable_addr) const;

private:
    // Check RTTI structure (MSVC)
    [[nodiscard]] bool check_msvc_rtti(Address vtable_addr, VTableInfo& info) const;

    std::shared_ptr<loader::Binary> binary_;
};

} // namespace picanha::analysis
