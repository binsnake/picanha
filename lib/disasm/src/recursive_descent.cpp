#include "picanha/disasm/recursive_descent.hpp"
#include <tbb/parallel_for.h>
#include <tbb/task_group.h>
#include <spdlog/spdlog.h>

namespace picanha::disasm {

RecursiveDescentDisassembler::RecursiveDescentDisassembler(
    std::shared_ptr<loader::Binary> binary,
    const RecursiveDescentConfig& config
)
    : binary_(std::move(binary))
    , context_(std::make_unique<DisassemblyContext>(binary_))
    , config_(config)
    , thread_decoders_([this]() { return Decoder(binary_->bitness()); })
{
    if (config_.num_threads == 0) {
        config_.num_threads = static_cast<std::size_t>(hardware_concurrency());
    }
}

void RecursiveDescentDisassembler::add_entry_point(Address addr) {
    if (context_->is_executable_address(addr)) {
        work_queue_.push_function(addr);
        context_->mark_function_entry(addr);
    }
}

void RecursiveDescentDisassembler::add_entry_points(std::span<const Address> addrs) {
    for (Address addr : addrs) {
        add_entry_point(addr);
    }
}

void RecursiveDescentDisassembler::set_function_callback(FunctionCallback callback) {
    function_callback_ = std::move(callback);
}

void RecursiveDescentDisassembler::set_instruction_callback(InstructionCallback callback) {
    instruction_callback_ = std::move(callback);
}

Result<DisassemblyResult> RecursiveDescentDisassembler::analyze() {
    DisassemblyResult result;

    // Initialize with known entry points
    initialize_entry_points();

    // Run parallel workers
    tbb::task_group workers;

    for (std::size_t i = 0; i < config_.num_threads; ++i) {
        workers.run([this]() { worker_loop(); });
    }

    workers.wait();

    // Gather results
    result.function_entries = context_->get_function_entries();
    result.code_addresses = context_->get_visited_addresses();
    result.instructions_decoded = instructions_decoded_.load();
    result.functions_found = result.function_entries.size();
    result.success = true;

    return result;
}

void RecursiveDescentDisassembler::initialize_entry_points() {
    // Add binary entry point
    add_entry_point(binary_->entry_point());

    // Add exported functions
    if (auto* exports = binary_->exports()) {
        for (const auto& exp : exports->exports) {
            if (!exp.is_forwarded && context_->is_executable_address(exp.address)) {
                add_entry_point(exp.address);
            }
        }
    }

    // Add functions from exception directory (x64)
    if (config_.use_exception_info) {
        if (auto* exceptions = binary_->exceptions()) {
            for (const auto& func : exceptions->functions) {
                add_entry_point(func.begin_address);
            }
        }
    }

    spdlog::debug("Initialized with {} entry points", context_->function_count());
}

void RecursiveDescentDisassembler::worker_loop() {
    DisasmWorkItem item;

    while (true) {
        // Try to get work
        if (!work_queue_.try_pop(item)) {
            // No work available, check if we're done
            if (work_queue_.is_complete()) {
                break;
            }
            // Spin briefly and retry
            std::this_thread::yield();
            continue;
        }

        // Process the work item
        WorkGuard guard(work_queue_);
        process_work_item(item);
        work_queue_.mark_processed();
    }
}

void RecursiveDescentDisassembler::process_work_item(const DisasmWorkItem& item) {
    if (!item.is_valid()) {
        return;
    }

    // Check if already visited
    if (!context_->mark_visited(item.address)) {
        return; // Already processed
    }

    // Mark as function entry if applicable
    if (item.is_function_entry) {
        context_->mark_function_entry(item.address);
        if (function_callback_) {
            function_callback_(item.address);
        }
    }

    // Disassemble the block
    disassemble_block(item.address);
}

void RecursiveDescentDisassembler::disassemble_block(Address addr) {
    // Read code from memory
    const auto& memory = binary_->memory();

    // Find the segment containing this address
    const auto* segment = memory.find_segment(addr);
    if (!segment || !segment->is_executable()) {
        return;
    }

    // Calculate available code size
    Address segment_end = segment->virtual_address + segment->virtual_size;
    Size available = (addr < segment_end) ? (segment_end - addr) : 0;

    if (available == 0) {
        return;
    }

    // Limit to reasonable block size
    available = std::min(available, static_cast<Size>(config_.max_block_size));

    // Get code bytes
    auto code_span = memory.read(addr, available);
    if (!code_span) {
        return;
    }

    // Get thread-local decoder
    auto& decoder = thread_decoders_.local();

    // Decode instructions until block terminator
    auto instructions = decoder.decode_until_terminator(*code_span, addr);

    for (const auto& instr : instructions) {
        // Already visited check (for overlapping blocks)
        if (!context_->mark_visited(instr.ip())) {
            break; // Hit previously decoded code
        }

        instructions_decoded_.fetch_add(1, std::memory_order_relaxed);

        // Invoke callback
        if (instruction_callback_) {
            instruction_callback_(instr);
        }

        // Analyze control flow
        auto targets = FlowAnalyzer::analyze(instr);
        handle_targets(targets, instr);
    }

    blocks_processed_.fetch_add(1, std::memory_order_relaxed);
}

void RecursiveDescentDisassembler::handle_targets(
    const std::vector<FlowTarget>& targets,
    const Instruction& instr
) {
    for (const auto& target : targets) {
        if (!target.is_valid()) {
            continue; // Indirect target, can't follow statically
        }

        Address addr = target.target;

        // Validate target address
        if (!context_->is_executable_address(addr)) {
            continue;
        }

        // Already visited?
        if (context_->is_visited(addr)) {
            continue;
        }

        // Determine priority and type
        WorkPriority priority = WorkPriority::Normal;
        bool is_function = false;

        if (target.is_call) {
            // Call target is a function entry
            context_->mark_call_target(addr);
            context_->mark_function_entry(addr);
            is_function = true;
            priority = WorkPriority::Normal;

            if (function_callback_) {
                function_callback_(addr);
            }

            // Don't follow calls if disabled
            if (!config_.follow_calls) {
                continue;
            }
        } else if (target.is_fallthrough) {
            // Sequential execution, high priority
            priority = WorkPriority::High;
        } else {
            // Jump target
            context_->mark_jump_target(addr);
            priority = WorkPriority::Normal;
        }

        // Queue the target
        DisasmWorkItem item;
        item.address = addr;
        item.priority = priority;
        item.is_function_entry = is_function;
        work_queue_.push(std::move(item));
    }
}

} // namespace picanha::disasm
