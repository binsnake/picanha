#include "picanha/analysis/cfg_builder.hpp"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <queue>

namespace picanha::analysis {

CFGBuilder::CFGBuilder(
    std::shared_ptr<loader::Binary> binary,
    const CFGBuilderConfig& config
)
    : binary_(std::move(binary))
    , config_(config)
    , decoder_(binary_->bitness())
{}

void CFGBuilder::add_entry_point(Address addr) {
    entry_points_.push_back(addr);
    block_starts_.insert(addr);
}

void CFGBuilder::add_jump_target(Address addr) {
    jump_targets_.insert(addr);
    block_starts_.insert(addr);
}

void CFGBuilder::add_call_target(Address addr) {
    call_targets_.insert(addr);
    if (config_.split_on_call_targets) {
        block_starts_.insert(addr);
    }
}

std::unique_ptr<CFG> CFGBuilder::build(Address entry_point) {
    cfg_ = std::make_unique<CFG>();
    all_instructions_.clear();
    block_starts_.clear();
    visited_.clear();

    // Entry point is first block start
    block_starts_.insert(entry_point);
    entry_points_.push_back(entry_point);

    // Phase 1: Decode (with absolute timeout)
    auto start_time = std::chrono::steady_clock::now();
    auto should_timeout = [&start_time]() {
        auto elapsed = std::chrono::steady_clock::now() - start_time;
        return elapsed > std::chrono::seconds(5);  // 5 second timeout per function
    };

    decode_function(entry_point, should_timeout);

    // Phase 2: Create blocks
    if (!should_timeout()) {
        spdlog::debug("CFG builder: creating blocks for 0x{:X}", entry_point);
        create_blocks();
        spdlog::debug("CFG builder: created {} blocks for 0x{:X}", cfg_->block_count(), entry_point);
    }

    // Phase 3: Add edges
    if (!should_timeout()) {
        spdlog::debug("CFG builder: adding edges for 0x{:X}", entry_point);
        add_edges();
        spdlog::debug("CFG builder: added edges for 0x{:X}", entry_point);
    }

    // Set entry block
    if (auto* entry_block = cfg_->find_block_starting_at(entry_point)) {
        cfg_->set_entry_block(entry_block->id());
    }

    // Find exit blocks (blocks ending with return)
    cfg_->for_each_block([this](BasicBlock& block) {
        if (block.terminator_type() == FlowType::Return) {
            cfg_->add_exit_block(block.id());
        }
    });

    return std::move(cfg_);
}

std::unique_ptr<CFG> CFGBuilder::build_from_instructions(
    Address entry_point,
    const std::vector<Instruction>& instructions
) {
    cfg_ = std::make_unique<CFG>();
    all_instructions_ = instructions;
    block_starts_.clear();

    // Entry point
    block_starts_.insert(entry_point);

    // Find all block boundaries from flow control
    for (const auto& instr : instructions) {
        auto targets = disasm::FlowAnalyzer::analyze(instr);

        for (const auto& target : targets) {
            if (target.is_valid() && !target.is_call) {
                block_starts_.insert(target.target);
            }
        }

        // Instruction after a branch is also a potential block start
        if (disasm::FlowAnalyzer::is_block_terminator(instr)) {
            block_starts_.insert(instr.next_ip());
        }
    }

    // Create blocks and edges
    create_blocks();
    add_edges();

    // Set entry
    if (auto* entry_block = cfg_->find_block_starting_at(entry_point)) {
        cfg_->set_entry_block(entry_block->id());
    }

    return std::move(cfg_);
}

void CFGBuilder::decode_function(Address entry) {
    // Call implementation with no-op timeout
    decode_function(entry, []() { return false; });
}

void CFGBuilder::decode_function(Address entry, std::function<bool()> should_timeout) {
    std::queue<Address> worklist;
    worklist.push(entry);

    std::size_t worklist_iterations = 0;
    constexpr std::size_t max_worklist_iterations = 100000;
    
    // Track largest worklist size for debugging
    std::size_t max_worklist_size = 1;
    Address last_logged_addr = 0;
    
    // Track consecutive empty decodes to detect hangs
    std::size_t consecutive_empty_decodes = 0;
    constexpr std::size_t max_consecutive_empty = 100;
    
    // Helper to check if address is within function bounds
    auto is_within_bounds = [this](Address addr) -> bool {
        // If no bounds specified, allow addresses near entry (within ~1MB for safety)
        if (config_.function_start == INVALID_ADDRESS ||
            config_.function_end == INVALID_ADDRESS) {
            // Use entry point as reference - don't follow jumps too far away
            if (!entry_points_.empty()) {
                Address func_entry = entry_points_.front();
                // Allow jumps within reasonable distance (256KB before or after entry)
                constexpr std::size_t max_distance = 256 * 1024;
                if (addr < func_entry && func_entry - addr > max_distance) return false;
                if (addr > func_entry && addr - func_entry > max_distance) return false;
            }
            return true;
        }
        return addr >= config_.function_start && addr < config_.function_end;
    };

    while (!worklist.empty()) {
        // Check timeout every iteration
        if (should_timeout()) {
            spdlog::warn("CFG builder: timeout at 0x{:X} after {} iterations", entry, worklist_iterations);
            break;
        }
        Address addr = worklist.front();
        worklist.pop();
        
        // Track max worklist size
        if (worklist.size() > max_worklist_size) {
            max_worklist_size = worklist.size();
        }

        // Safety: limit total worklist iterations to prevent infinite loops
        if (++worklist_iterations > max_worklist_iterations) {
            spdlog::warn("CFG builder: hit max worklist iterations at 0x{:X}, worklist size: {}, max size: {}", 
                entry, worklist.size(), max_worklist_size);
            break;
        }
        
        // Log progress every 10000 iterations for debugging hangs
        if (worklist_iterations % 10000 == 0) {
            spdlog::debug("CFG builder: iteration {} at 0x{:X}, worklist: {}, visited: {}, instructions: {}",
                worklist_iterations, addr, worklist.size(), visited_.size(), all_instructions_.size());
        }

        if (visited_.count(addr)) continue;
        if (!binary_->memory().is_executable(addr)) continue;

        // Check instruction limit
        if (all_instructions_.size() >= config_.max_instructions) {
            spdlog::debug("CFG builder: hit max instructions ({}) at 0x{:X}", config_.max_instructions, entry);
            break;
        }
        
        // Log every 1000 unique addresses decoded for debugging
        if (visited_.size() % 1000 == 0 && last_logged_addr != addr) {
            last_logged_addr = addr;
            spdlog::debug("CFG builder: decoded {} instructions at 0x{:X}, worklist: {}",
                visited_.size(), addr, worklist.size());
        }

        auto instructions = decode_block(addr);
        
        // Track consecutive empty decodes
        if (instructions.empty()) {
            consecutive_empty_decodes++;
            if (consecutive_empty_decodes >= max_consecutive_empty) {
                spdlog::warn("CFG builder: breaking due to {} consecutive empty decodes at 0x{:X}",
                    consecutive_empty_decodes, entry);
                break;
            }
        } else {
            consecutive_empty_decodes = 0;
        }
        
        // Debug: Log instruction count
        if (worklist_iterations % 1000 == 0 || instructions.empty()) {
            spdlog::debug("CFG builder: decoded {} instructions at 0x{:X}, worklist: {} (iter: {})",
                instructions.size(), addr, worklist.size(), worklist_iterations);
        }

        for (const auto& instr : instructions) {
            if (visited_.count(instr.ip())) continue;
            visited_.insert(instr.ip());

            all_instructions_.push_back(instr);

            // Check instruction limit inside loop too
            if (all_instructions_.size() >= config_.max_instructions) {
                break;
            }

            // Analyze flow
            auto targets = disasm::FlowAnalyzer::analyze(instr);

            for (const auto& target : targets) {
                if (!target.is_valid()) continue;

                if (target.is_call) {
                    call_targets_.insert(target.target);
                    if (config_.follow_calls) {
                        worklist.push(target.target);
                        block_starts_.insert(target.target);
                    }
                } else if (!target.is_fallthrough) {
                    // Jump target - check if it's a potential tail call
                    // Unconditional jumps outside function bounds are likely tail calls
                    if (!is_within_bounds(target.target)) {
                        // This is likely a tail call - don't follow it
                        // Just mark that this block has a jump out
                        continue;
                    }

                    jump_targets_.insert(target.target);
                    block_starts_.insert(target.target);
                    worklist.push(target.target);
                } else {
                    // Fallthrough - continue decoding if within bounds
                    if (is_within_bounds(target.target)) {
                        worklist.push(target.target);
                    }
                }
            }

            // After a terminator, the next instruction starts a new block
            if (disasm::FlowAnalyzer::is_block_terminator(instr)) {
                block_starts_.insert(instr.next_ip());
            }
        }

        // Check block limit (estimated from instruction count)
        if (block_starts_.size() > config_.max_blocks) {
            spdlog::debug("CFG builder: hit max blocks ({}) at 0x{:X}", config_.max_blocks, entry);
            break;
        }
    }
    
    spdlog::debug("CFG builder: worklist loop exited at 0x{:X}, iterations: {}, instructions: {}, blocks: {}",
        entry, worklist_iterations, all_instructions_.size(), block_starts_.size());

    // Sort instructions by address
    spdlog::debug("CFG builder: starting sort for 0x{:X} with {} instructions", entry, all_instructions_.size());
    std::sort(all_instructions_.begin(), all_instructions_.end(),
        [](const Instruction& a, const Instruction& b) {
            return a.ip() < b.ip();
        });
    spdlog::debug("CFG builder: sort completed for 0x{:X}", entry);

    // Remove duplicates
    spdlog::debug("CFG builder: removing duplicates for 0x{:X}", entry);
    all_instructions_.erase(
        std::unique(all_instructions_.begin(), all_instructions_.end(),
            [](const Instruction& a, const Instruction& b) {
                return a.ip() == b.ip();
            }),
        all_instructions_.end()
    );
    spdlog::debug("CFG builder: decode_function completed for 0x{:X} with {} instructions", entry, all_instructions_.size());
}

std::vector<Instruction> CFGBuilder::decode_block(Address addr) {
    // Get code from memory - limit to smaller size to prevent huge decodes
    std::size_t read_size = std::min(config_.max_block_size, static_cast<std::size_t>(4096));
    auto code = binary_->memory().read(addr, read_size);
    if (!code) {
        return {};
    }
    
    // Decode with instruction limit per block
    auto instructions = decoder_.decode_until_terminator(*code, addr);
    
    // Safety: if we decoded too many instructions, something might be wrong
    constexpr std::size_t max_block_instructions = 1000;
    if (instructions.size() > max_block_instructions) {
        spdlog::warn("CFG builder: block at 0x{:X} has {} instructions, truncating to {}", 
            addr, instructions.size(), max_block_instructions);
        instructions.resize(max_block_instructions);
    }

    return instructions;
}

void CFGBuilder::create_blocks() {
    if (all_instructions_.empty()) return;

    BasicBlock* current_block = nullptr;

    for (const auto& instr : all_instructions_) {
        Address addr = instr.ip();

        // Check if this starts a new block
        bool new_block = (current_block == nullptr) ||
                         block_starts_.count(addr) ||
                         (current_block && disasm::FlowAnalyzer::is_block_terminator(
                             *current_block->last_instruction()));

        if (new_block) {
            current_block = &cfg_->create_block(addr);
        }

        current_block->add_instruction(instr);

        // Update block flags
        if (instr.is_call()) {
            current_block->set_has_call(true);
        }
        if (instr.flow_type() == FlowType::IndirectJump ||
            instr.flow_type() == FlowType::IndirectCall) {
            current_block->set_has_indirect(true);
        }
    }
}

void CFGBuilder::add_edges() {
    cfg_->for_each_block([this](BasicBlock& block) {
        const auto* last = block.last_instruction();
        if (!last) return;

        auto targets = disasm::FlowAnalyzer::analyze(*last);

        for (const auto& target : targets) {
            if (!target.is_valid()) {
                // Indirect - add edge to nowhere (for tracking)
                continue;
            }

            if (target.is_call && !config_.follow_calls) {
                // Skip call edges
                continue;
            }

            auto* target_block = cfg_->find_block_starting_at(target.target);
            if (!target_block) {
                // Target might be in the middle of a block (shouldn't happen if properly split)
                target_block = cfg_->find_block_at(target.target);
            }

            if (target_block) {
                EdgeType edge_type;
                if (target.is_call) {
                    edge_type = EdgeType::Call;
                } else if (target.is_fallthrough) {
                    edge_type = target.is_conditional ? EdgeType::ConditionalFalse : EdgeType::Fallthrough;
                } else if (target.is_conditional) {
                    edge_type = EdgeType::ConditionalTrue;
                } else {
                    edge_type = EdgeType::UnconditionalJump;
                }

                cfg_->add_edge(block.id(), target_block->id(), edge_type);
            }
        }
    });
}

bool CFGBuilder::is_block_boundary(Address addr) const {
    return block_starts_.count(addr) > 0;
}

} // namespace picanha::analysis
