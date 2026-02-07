#include "picanha/disasm/disassembly_context.hpp"

namespace picanha::disasm {

DisassemblyContext::DisassemblyContext(std::shared_ptr<loader::Binary> binary)
    : binary_(std::move(binary))
{}

bool DisassemblyContext::mark_visited(Address addr) {
    return visited_addresses_.insert(addr).second;
}

bool DisassemblyContext::is_visited(Address addr) const {
    return visited_addresses_.count(addr) > 0;
}

bool DisassemblyContext::mark_function_entry(Address addr) {
    return function_entries_.insert(addr).second;
}

bool DisassemblyContext::is_function_entry(Address addr) const {
    return function_entries_.count(addr) > 0;
}

bool DisassemblyContext::mark_call_target(Address addr) {
    return call_targets_.insert(addr).second;
}

bool DisassemblyContext::mark_jump_target(Address addr) {
    return jump_targets_.insert(addr).second;
}

std::vector<Address> DisassemblyContext::get_visited_addresses() const {
    std::vector<Address> result;
    result.reserve(visited_addresses_.size());
    for (const auto& addr : visited_addresses_) {
        result.push_back(addr);
    }
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<Address> DisassemblyContext::get_function_entries() const {
    std::vector<Address> result;
    result.reserve(function_entries_.size());
    for (const auto& addr : function_entries_) {
        result.push_back(addr);
    }
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<Address> DisassemblyContext::get_call_targets() const {
    std::vector<Address> result;
    result.reserve(call_targets_.size());
    for (const auto& addr : call_targets_) {
        result.push_back(addr);
    }
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<Address> DisassemblyContext::get_jump_targets() const {
    std::vector<Address> result;
    result.reserve(jump_targets_.size());
    for (const auto& addr : jump_targets_) {
        result.push_back(addr);
    }
    std::sort(result.begin(), result.end());
    return result;
}

bool DisassemblyContext::is_valid_code_address(Address addr) const {
    return binary_->memory().is_valid_address(addr);
}

bool DisassemblyContext::is_executable_address(Address addr) const {
    return binary_->memory().is_executable(addr);
}

} // namespace picanha::disasm
