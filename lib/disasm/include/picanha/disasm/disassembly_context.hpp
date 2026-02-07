#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/parallel.hpp>
#include <picanha/core/hash.hpp>
#include <picanha/loader/binary.hpp>
#include <atomic>
#include <memory>

namespace picanha::disasm {

// Shared context for parallel disassembly
class DisassemblyContext {
public:
    explicit DisassemblyContext(std::shared_ptr<loader::Binary> binary);

    // Binary access
    [[nodiscard]] const loader::Binary& binary() const noexcept { return *binary_; }
    [[nodiscard]] std::shared_ptr<loader::Binary> binary_ptr() const noexcept { return binary_; }

    // Address tracking
    // Mark an address as visited (returns true if newly visited)
    [[nodiscard]] bool mark_visited(Address addr);

    // Check if address was visited
    [[nodiscard]] bool is_visited(Address addr) const;

    // Mark address as a function entry
    [[nodiscard]] bool mark_function_entry(Address addr);

    // Check if address is a known function entry
    [[nodiscard]] bool is_function_entry(Address addr) const;

    // Mark address as a call target
    [[nodiscard]] bool mark_call_target(Address addr);

    // Mark address as a jump target
    [[nodiscard]] bool mark_jump_target(Address addr);

    // Get all visited addresses (for debugging/analysis)
    [[nodiscard]] std::vector<Address> get_visited_addresses() const;

    // Get all function entries
    [[nodiscard]] std::vector<Address> get_function_entries() const;

    // Get all call targets
    [[nodiscard]] std::vector<Address> get_call_targets() const;

    // Get all jump targets
    [[nodiscard]] std::vector<Address> get_jump_targets() const;

    // Iterate over call targets
    template<typename Func>
    void for_each_call_target(Func&& func) const {
        for (const auto& addr : call_targets_) {
            func(addr);
        }
    }

    // Iterate over jump targets
    template<typename Func>
    void for_each_jump_target(Func&& func) const {
        for (const auto& addr : jump_targets_) {
            func(addr);
        }
    }

    // Statistics
    [[nodiscard]] std::size_t visited_count() const noexcept {
        return visited_addresses_.size();
    }

    [[nodiscard]] std::size_t function_count() const noexcept {
        return function_entries_.size();
    }

    // Validation
    [[nodiscard]] bool is_valid_code_address(Address addr) const;
    [[nodiscard]] bool is_executable_address(Address addr) const;

private:
    std::shared_ptr<loader::Binary> binary_;

    // Thread-safe address sets
    ConcurrentSet<Address, AddressHash> visited_addresses_;
    ConcurrentSet<Address, AddressHash> function_entries_;
    ConcurrentSet<Address, AddressHash> call_targets_;
    ConcurrentSet<Address, AddressHash> jump_targets_;
};

} // namespace picanha::disasm
