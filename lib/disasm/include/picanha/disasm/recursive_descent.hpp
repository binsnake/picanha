#pragma once

#include "picanha/disasm/decoder.hpp"
#include "picanha/disasm/disassembly_context.hpp"
#include "picanha/disasm/work_queue.hpp"
#include "picanha/disasm/flow_analyzer.hpp"
#include "picanha/disasm/instruction_info.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/result.hpp>
#include <picanha/core/parallel.hpp>
#include <picanha/loader/binary.hpp>
#include <memory>
#include <functional>
#include <vector>

namespace picanha::disasm {

// Configuration for recursive descent
struct RecursiveDescentConfig {
    std::size_t max_instructions_per_function{100000};
    std::size_t max_block_size{10000};
    std::size_t num_threads{0};  // 0 = auto (hardware concurrency)
    bool follow_calls{true};
    bool use_exception_info{true};  // Use x64 RUNTIME_FUNCTION for hints
    bool speculative_decode{false}; // Try decoding potential code regions
};

// Result of disassembly
struct DisassemblyResult {
    std::vector<Address> function_entries;
    std::vector<Address> code_addresses;  // All discovered code addresses
    std::size_t instructions_decoded{0};
    std::size_t functions_found{0};
    bool success{true};
    std::string error;
};

// Callback for discovered functions
using FunctionCallback = std::function<void(Address entry)>;

// Callback for decoded instructions
using InstructionCallback = std::function<void(const Instruction& instr)>;

// Main recursive descent disassembler
class RecursiveDescentDisassembler {
public:
    explicit RecursiveDescentDisassembler(
        std::shared_ptr<loader::Binary> binary,
        const RecursiveDescentConfig& config = {}
    );

    // Run full analysis
    [[nodiscard]] Result<DisassemblyResult> analyze();

    // Add entry point to analyze
    void add_entry_point(Address addr);

    // Add multiple entry points
    void add_entry_points(std::span<const Address> addrs);

    // Set callbacks
    void set_function_callback(FunctionCallback callback);
    void set_instruction_callback(InstructionCallback callback);

    // Get context (for inspection during/after analysis)
    [[nodiscard]] const DisassemblyContext& context() const noexcept { return *context_; }
    [[nodiscard]] DisassemblyContext& context() noexcept { return *context_; }

private:
    // Initialize analysis with known entry points
    void initialize_entry_points();

    // Process a single work item
    void process_work_item(const DisasmWorkItem& item);

    // Disassemble a basic block starting at addr
    void disassemble_block(Address addr);

    // Handle discovered targets
    void handle_targets(const std::vector<FlowTarget>& targets, const Instruction& instr);

    // Worker function for parallel processing
    void worker_loop();

    std::shared_ptr<loader::Binary> binary_;
    std::unique_ptr<DisassemblyContext> context_;
    RecursiveDescentConfig config_;
    DisasmWorkQueue work_queue_;

    // Thread-local decoders
    ThreadLocal<Decoder> thread_decoders_;

    // Callbacks
    FunctionCallback function_callback_;
    InstructionCallback instruction_callback_;

    // Statistics
    std::atomic<std::size_t> instructions_decoded_{0};
    std::atomic<std::size_t> blocks_processed_{0};
};

} // namespace picanha::disasm
