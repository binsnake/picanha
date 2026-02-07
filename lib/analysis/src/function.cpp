#include "picanha/analysis/function.hpp"
#include <limits>

namespace picanha::analysis {

Function::Function(FunctionId id, Address entry)
    : id_(id)
    , entry_address_(entry)
{}

Address Function::start_address() const noexcept {
    Address min_addr = std::numeric_limits<Address>::max();

    cfg_.for_each_block([&min_addr](const BasicBlock& block) {
        if (block.start_address() < min_addr) {
            min_addr = block.start_address();
        }
    });

    return min_addr == std::numeric_limits<Address>::max() ? entry_address_ : min_addr;
}

Address Function::end_address() const noexcept {
    Address max_addr = 0;

    cfg_.for_each_block([&max_addr](const BasicBlock& block) {
        if (block.end_address() > max_addr) {
            max_addr = block.end_address();
        }
    });

    return max_addr == 0 ? entry_address_ : max_addr;
}

Size Function::size() const noexcept {
    // Note: This is the span, not the actual code size (may include gaps)
    Address start = start_address();
    Address end = end_address();
    return end > start ? end - start : 0;
}

BasicBlock* Function::entry_block() {
    return cfg_.entry_block();
}

const BasicBlock* Function::entry_block() const {
    return cfg_.entry_block();
}

} // namespace picanha::analysis
