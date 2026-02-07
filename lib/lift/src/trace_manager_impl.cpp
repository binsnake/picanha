#include <picanha/lift/trace_manager_impl.hpp>

#include <format>

namespace picanha::lift {

PicanhaTraceManager::PicanhaTraceManager(std::shared_ptr<loader::Binary> binary)
    : binary_(std::move(binary))
{
}

PicanhaTraceManager::~PicanhaTraceManager() = default;

std::string PicanhaTraceManager::TraceName(std::uint64_t addr) {
    // Generate a name like "sub_140001000" for the trace
    return std::format("sub_{:X}", addr);
}

void PicanhaTraceManager::SetLiftedTraceDefinition(std::uint64_t addr, llvm::Function* func) {
    if (func) {
        lifted_traces_[addr] = func;
    }
}

llvm::Function* PicanhaTraceManager::GetLiftedTraceDeclaration(std::uint64_t addr) {
    // First check if we have a definition
    auto it = lifted_traces_.find(addr);
    if (it != lifted_traces_.end()) {
        return it->second;
    }

    // Check for existing declaration
    it = declared_traces_.find(addr);
    if (it != declared_traces_.end()) {
        return it->second;
    }

    // No declaration exists - remill will create one
    return nullptr;
}

llvm::Function* PicanhaTraceManager::GetLiftedTraceDefinition(std::uint64_t addr) {
    auto it = lifted_traces_.find(addr);
    if (it != lifted_traces_.end()) {
        return it->second;
    }
    return nullptr;
}

bool PicanhaTraceManager::TryReadExecutableByte(std::uint64_t addr, std::uint8_t* byte) {
    if (!binary_ || !byte) {
        return false;
    }

    // Check if address is within an executable section
    if (!is_executable(addr)) {
        return false;
    }

    // Try to read the byte from the binary using memory map
    auto result = binary_->memory().read(static_cast<Address>(addr), 1);
    if (result.has_value() && !result->empty()) {
        *byte = (*result)[0];
        return true;
    }

    return false;
}

bool PicanhaTraceManager::is_executable(std::uint64_t addr) const {
    if (!binary_) {
        return false;
    }

    // Check each section for executable permissions
    for (const auto& section : binary_->sections()) {
        if (section.is_executable()) {
            Address start = section.virtual_address;
            Address end = start + section.virtual_size;
            if (addr >= start && addr < end) {
                return true;
            }
        }
    }

    return false;
}

void PicanhaTraceManager::clear() {
    lifted_traces_.clear();
    declared_traces_.clear();
}

} // namespace picanha::lift
