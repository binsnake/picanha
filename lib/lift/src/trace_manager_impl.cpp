#include <picanha/lift/trace_manager_impl.hpp>

#include <spdlog/spdlog.h>

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

void PicanhaTraceManager::ForEachDevirtualizedTarget(
    const remill::Instruction& inst,
    std::function<void(uint64_t, remill::DevirtualizedTargetKind)> func)
{
    auto targets = analyze_jump_table(inst);
    for (uint64_t target : targets) {
        func(target, remill::DevirtualizedTargetKind::kTraceLocal);
    }
}

std::vector<uint64_t> PicanhaTraceManager::analyze_jump_table(
    const remill::Instruction& inst) const
{
    std::vector<uint64_t> targets;
    if (!binary_) return targets;

    // Decode instructions around the indirect jump using picanha's decoder
    // and delegate to JumpTableAnalyzer which uses DAG/pattern matching
    const uint64_t scan_window = 128;
    const uint64_t scan_start = (inst.pc >= scan_window) ? inst.pc - scan_window : 0;
    const uint64_t scan_end = inst.pc + 15; // max x86 instruction length
    const uint64_t scan_size = scan_end - scan_start;

    auto code_bytes = binary_->memory().read(scan_start, scan_size);
    if (!code_bytes || code_bytes->empty()) return targets;

    // Decode all instructions in the scan window
    disasm::Decoder decoder(binary_->bitness());
    ByteSpan code_span(*code_bytes);
    auto instructions = decoder.decode_all(code_span, scan_start);
    if (instructions.empty()) return targets;

    // Build a basic block for the analyzer
    analysis::BasicBlock block(0, scan_start);
    for (const auto& instr : instructions) {
        block.add_instruction(instr);
    }

    // Use JumpTableAnalyzer with DAG-based pattern matching
    analysis::JumpTableConfig config;
    config.max_entries = 4096;
    config.min_entries = 2;
    config.require_bounds_check = false;
    config.allow_relative_tables = true;

    analysis::JumpTableAnalyzer analyzer(binary_, config);
    auto result = analyzer.analyze_indirect_jump(
        block, static_cast<Address>(inst.pc));

    if (result && result->is_valid()) {
        targets = result->targets;
        spdlog::info(
            "Devirtualized indirect jump at 0x{:X}: {} targets "
            "from table at 0x{:X} ({})",
            inst.pc, targets.size(), result->table_address,
            analysis::jump_table_entry_type_name(result->entry_type));
    }

    return targets;
}

void PicanhaTraceManager::clear() {
    lifted_traces_.clear();
    declared_traces_.clear();
}

} // namespace picanha::lift
