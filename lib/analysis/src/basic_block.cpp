#include "picanha/analysis/basic_block.hpp"
#include <algorithm>

namespace picanha::analysis {

BasicBlock::BasicBlock(BlockId id, Address start_address)
    : id_(id)
    , start_address_(start_address)
    , end_address_(start_address)
{}

const Instruction* BasicBlock::instruction_at(Address addr) const {
    // Binary search since instructions are sorted by address
    auto it = std::lower_bound(
        instructions_.begin(),
        instructions_.end(),
        addr,
        [](const Instruction& instr, Address a) {
            return instr.ip() < a;
        }
    );

    if (it != instructions_.end() && it->ip() == addr) {
        return &(*it);
    }
    return nullptr;
}

} // namespace picanha::analysis
