#include "picanha/analysis/function_detector.hpp"
#include <picanha/disasm/flow_analyzer.hpp>
#include <spdlog/spdlog.h>
#include <algorithm>
#include <execution>

namespace picanha::analysis {

FunctionDetector::FunctionDetector(
    std::shared_ptr<loader::Binary> binary,
    std::shared_ptr<disasm::DisassemblyContext> context,
    const FunctionDetectorConfig& config
)
    : binary_(std::move(binary))
    , context_(std::move(context))
    , config_(config)
{}

void FunctionDetector::detect() {
    detect(nullptr);
}

void FunctionDetector::detect(DetectionProgressCallback callback) {
    progress_callback_ = std::move(callback);
    candidates_.clear();
    functions_.clear();
    address_to_function_.clear();
    progress_counter_ = 0;

    // Phase 1: Collect candidates from various sources
    if (progress_callback_) {
        progress_callback_(0, 6, "Collecting from exception info");
    }

    if (config_.use_exception_info) {
        collect_from_exceptions();
    }

    if (progress_callback_) {
        progress_callback_(1, 6, "Collecting from exports");
    }

    if (config_.use_exports) {
        collect_from_exports();
    }

    if (progress_callback_) {
        progress_callback_(2, 6, "Collecting from imports");
    }

    if (config_.use_imports) {
        collect_from_imports();
    }

    if (progress_callback_) {
        progress_callback_(3, 6, "Collecting from call targets");
    }

    if (config_.use_call_targets) {
        collect_from_call_targets();
    }

    if (progress_callback_) {
        progress_callback_(4, 6, "Scanning for prologues");
    }

    if (config_.use_prologue_patterns) {
        collect_from_prologue_patterns();
    }

    if (config_.use_heuristics) {
        collect_from_heuristics();
    }

    // Phase 2: Deduplicate
    deduplicate_candidates();

    // Phase 3: Build functions
    if (progress_callback_) {
        progress_callback_(5, 6, "Building functions");
    }

    build_functions();

    // Phase 4: Analyze call graph
    if (config_.analyze_calls) {
        analyze_call_graph();
    }

    if (progress_callback_) {
        progress_callback_(6, 6, "Complete");
    }
}

void FunctionDetector::collect_from_exceptions() {
    const auto* exceptions = binary_->exceptions();
    if (!exceptions) {
        spdlog::warn("No exception info available");
        return;
    }

    spdlog::info("Exception directory has {} entries", exceptions->functions.size());

    for (const auto& entry : exceptions->functions) {
        FunctionCandidate candidate;
        candidate.address = entry.begin_address;
        candidate.source = FunctionSource::ExceptionInfo;
        candidate.confidence = 100;  // Highest confidence
        candidate.end_address = entry.end_address;
        candidate.unwind_info = binary_->image_base() + entry.unwind_info_rva;

        candidates_.push_back(candidate);
    }
}

void FunctionDetector::collect_from_exports() {
    const auto* exports = binary_->exports();
    if (!exports) return;

    for (const auto& exp : exports->exports) {
        if (exp.is_forwarded) continue;

        if (!is_valid_code_address(exp.address)) continue;

        FunctionCandidate candidate;
        candidate.address = exp.address;
        candidate.source = FunctionSource::Export;
        candidate.name = exp.name;
        candidate.confidence = 95;

        candidates_.push_back(candidate);
    }
}

void FunctionDetector::collect_from_imports() {
    const auto* imports = binary_->imports();
    if (!imports) return;

    for (const auto& module : imports->modules) {
        // Import thunks are typically at the IAT
        // The actual thunk code (jmp [IAT]) is elsewhere
        // We look for jmp stubs that target the IAT

        // For now, imports are handled differently - they're not "functions"
        // in our binary but references to external functions
        (void)module;
    }
}

void FunctionDetector::collect_from_call_targets() {
    // Get all addresses that were targets of call instructions
    // from the disassembly context
    context_->for_each_call_target([this](Address target) {
        if (!is_valid_code_address(target)) return;

        // Check if we already have this from a higher-confidence source
        bool found = false;
        for (const auto& c : candidates_) {
            if (c.address == target) {
                found = true;
                break;
            }
        }

        if (!found) {
            FunctionCandidate candidate;
            candidate.address = target;
            candidate.source = FunctionSource::CallTarget;
            candidate.confidence = 80;
            candidates_.push_back(candidate);
        }
    });
}

void FunctionDetector::collect_from_prologue_patterns() {
    // Scan executable sections for common function prologues
    const auto& sections = binary_->sections();

    for (const auto& section : sections) {
        if (!section.is_executable()) {
            continue;
        }

        Address start = section.virtual_address;
        Address end = start + section.virtual_size;

        // Read section data
        auto data = binary_->memory().read(start, section.virtual_size);
        if (!data) continue;

        const std::uint8_t* bytes = data->data();
        std::size_t size = data->size();

        for (std::size_t i = 0; i < size - 4; ++i) {
            Address addr = start + i;

            // Skip if already a candidate
            bool exists = false;
            for (const auto& c : candidates_) {
                if (c.address == addr) {
                    exists = true;
                    break;
                }
            }
            if (exists) continue;

            // Check for common x64 prologues
            bool is_prologue = false;

            // push rbp; mov rbp, rsp (0x55 0x48 0x89 0xE5)
            if (config_.detect_push_rbp && i + 3 < size) {
                if (bytes[i] == 0x55 && bytes[i+1] == 0x48 &&
                    bytes[i+2] == 0x89 && bytes[i+3] == 0xE5) {
                    is_prologue = true;
                }
            }

            // sub rsp, imm8 (0x48 0x83 0xEC xx)
            if (config_.detect_sub_rsp && i + 3 < size) {
                if (bytes[i] == 0x48 && bytes[i+1] == 0x83 && bytes[i+2] == 0xEC) {
                    is_prologue = true;
                }
            }

            // sub rsp, imm32 (0x48 0x81 0xEC xx xx xx xx)
            if (config_.detect_sub_rsp && i + 6 < size) {
                if (bytes[i] == 0x48 && bytes[i+1] == 0x81 && bytes[i+2] == 0xEC) {
                    is_prologue = true;
                }
            }

            // mov [rsp+8], rcx (0x48 0x89 0x4C 0x24 0x08) - shadow space setup
            if (config_.detect_mov_rsp && i + 4 < size) {
                if (bytes[i] == 0x48 && bytes[i+1] == 0x89 &&
                    bytes[i+2] == 0x4C && bytes[i+3] == 0x24) {
                    is_prologue = true;
                }
            }

            // push rbx (0x53) at aligned address often starts functions
            if (config_.detect_push_rbp && (addr & 0xF) == 0) {
                if (bytes[i] == 0x53 || bytes[i] == 0x55 || bytes[i] == 0x56 || bytes[i] == 0x57) {
                    // Additional check: followed by more pushes or sub rsp
                    if (i + 1 < size) {
                        std::uint8_t next = bytes[i + 1];
                        if (next == 0x48 || next == 0x53 || next == 0x55 ||
                            next == 0x56 || next == 0x57) {
                            is_prologue = true;
                        }
                    }
                }
            }

            if (is_prologue) {
                FunctionCandidate candidate;
                candidate.address = addr;
                candidate.source = FunctionSource::ProloguePattern;
                candidate.confidence = 50;
                candidates_.push_back(candidate);

                // Skip ahead to avoid detecting overlapping prologues
                i += 3;
            }
        }
    }
}

void FunctionDetector::collect_from_heuristics() {
    // Additional heuristics:
    // - Addresses following ret/int3 padding that are 16-byte aligned
    // - Addresses referenced by data that look like function pointers

    // This is a lighter-weight pass for now
}

void FunctionDetector::deduplicate_candidates() {
    // Sort by address, then by confidence (higher first)
    std::sort(candidates_.begin(), candidates_.end(),
        [](const FunctionCandidate& a, const FunctionCandidate& b) {
            if (a.address != b.address) return a.address < b.address;
            return a.confidence > b.confidence;
        });

    // Keep only the highest-confidence entry per address
    auto it = std::unique(candidates_.begin(), candidates_.end(),
        [](const FunctionCandidate& a, const FunctionCandidate& b) {
            return a.address == b.address;
        });
    candidates_.erase(it, candidates_.end());

    // Filter by minimum confidence
    candidates_.erase(
        std::remove_if(candidates_.begin(), candidates_.end(),
            [this](const FunctionCandidate& c) {
                return c.confidence < config_.min_confidence;
            }),
        candidates_.end()
    );

    // Limit total count
    if (candidates_.size() > config_.max_functions) {
        candidates_.resize(config_.max_functions);
    }
}

void FunctionDetector::build_functions() {
    spdlog::info("build_functions: {} candidates, build_cfg={}", candidates_.size(), config_.build_cfg);

    if (!config_.build_cfg) {
        // Just create functions without CFGs
        functions_.reserve(candidates_.size());
        FunctionId next_id = 0;

        for (const auto& candidate : candidates_) {
            Function func(next_id, candidate.address);
            func.set_name(candidate.name);

            // Set type based on source
            switch (candidate.source) {
                case FunctionSource::Import:
                    func.set_type(FunctionType::Import);
                    break;
                case FunctionSource::Export:
                    func.set_type(FunctionType::Export);
                    break;
                default:
                    func.set_type(FunctionType::Normal);
                    break;
            }

            address_to_function_.insert({candidate.address, next_id});
            functions_.push_back(std::move(func));
            ++next_id;
        }
        return;
    }

    // Build CFGs in parallel
    spdlog::info("Building CFGs for {} functions...", candidates_.size());
    functions_.resize(candidates_.size());

    std::atomic<std::size_t> completed{0};

    tbb::parallel_for(
        tbb::blocked_range<std::size_t>(0, candidates_.size()),
        [this, &completed](const tbb::blocked_range<std::size_t>& range) {
            for (std::size_t i = range.begin(); i != range.end(); ++i) {
                const auto& candidate = candidates_[i];

                // Configure CFG builder with function bounds if available
                CFGBuilderConfig cfg_config;
                cfg_config.function_start = candidate.address;
                if (candidate.end_address != INVALID_ADDRESS) {
                    cfg_config.function_end = candidate.end_address;
                }

                CFGBuilder builder(binary_, cfg_config);
                FunctionId id = static_cast<FunctionId>(i);

                // Progress logging
                auto done = ++completed;
                if (done % 100 == 0 || done == candidates_.size()) {
                    spdlog::info("  CFG progress: {}/{}", done, candidates_.size());
                }

                Function func(id, candidate.address);
                func.set_name(candidate.name);

                // Set type based on source
                switch (candidate.source) {
                    case FunctionSource::Import:
                        func.set_type(FunctionType::Import);
                        break;
                    case FunctionSource::Export:
                        func.set_type(FunctionType::Export);
                        break;
                    default:
                        func.set_type(FunctionType::Normal);
                        break;
                }

                // Build CFG
                auto cfg = builder.build(candidate.address);
                if (cfg) {
                    // Analyze CFG properties
                    cfg->compute_dominators();
                    cfg->detect_loops();

                    // Set function flags based on CFG
                    if (cfg->loop_headers().empty()) {
                        // No loops - might be leaf if also no calls
                    } else {
                        func.set_flag(FunctionFlags::HasLoops);
                    }

                    // Check for leaf function (no calls)
                    bool has_calls = false;
                    cfg->for_each_block([&has_calls](const BasicBlock& block) {
                        if (block.has_call()) {
                            has_calls = true;
                        }
                    });

                    if (!has_calls) {
                        func.set_flag(FunctionFlags::IsLeaf);
                    }

                    // Check for indirect control flow
                    cfg->for_each_block([&func](const BasicBlock& block) {
                        if (block.has_indirect()) {
                            if (block.terminator_type() == FlowType::IndirectCall) {
                                func.set_flag(FunctionFlags::HasIndirectCalls);
                            } else if (block.terminator_type() == FlowType::IndirectJump) {
                                func.set_flag(FunctionFlags::HasIndirectJumps);
                            }
                        }
                    });

                    func.set_cfg(std::move(*cfg));
                }

                address_to_function_.insert({candidate.address, id});
                functions_[i] = std::move(func);

                // Update progress
                ++progress_counter_;
            }
        }
    );
}

void FunctionDetector::analyze_call_graph() {
    // For each function, find call targets and link callers/callees
    tbb::parallel_for(
        tbb::blocked_range<std::size_t>(0, functions_.size()),
        [this](const tbb::blocked_range<std::size_t>& range) {
            for (std::size_t i = range.begin(); i != range.end(); ++i) {
                auto& func = functions_[i];

                func.cfg().for_each_block([this, &func](const BasicBlock& block) {
                    for (const auto& instr : block.instructions()) {
                        if (instr.is_call()) {
                            auto targets = disasm::FlowAnalyzer::analyze(instr);
                            for (const auto& target : targets) {
                                if (target.is_valid() && target.is_call) {
                                    // Find target function
                                    auto callee_it = address_to_function_.find(target.target);
                                    if (callee_it != address_to_function_.end()) {
                                        func.add_callee(callee_it->second);
                                    }
                                }
                            }
                        }
                    }
                });
            }
        }
    );

    // Build caller lists from callee lists
    for (auto& func : functions_) {
        for (FunctionId callee_id : func.callees()) {
            if (callee_id < functions_.size()) {
                functions_[callee_id].add_caller(func.id());
            }
        }
    }
}

bool FunctionDetector::check_prologue(Address addr) const {
    auto data = binary_->memory().read(addr, 16);
    if (!data || data->empty()) return false;

    const std::uint8_t* bytes = data->data();
    std::size_t size = data->size();

    // Check common prologues
    if (size >= 4 && bytes[0] == 0x55 && bytes[1] == 0x48 &&
        bytes[2] == 0x89 && bytes[3] == 0xE5) {
        return true;  // push rbp; mov rbp, rsp
    }

    if (size >= 4 && bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) {
        return true;  // sub rsp, imm8
    }

    if (size >= 7 && bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC) {
        return true;  // sub rsp, imm32
    }

    return false;
}

bool FunctionDetector::is_valid_code_address(Address addr) const {
    return binary_->memory().is_executable(addr);
}

Function* FunctionDetector::find_function(Address entry) {
    auto it = address_to_function_.find(entry);
    if (it != address_to_function_.end() && it->second < functions_.size()) {
        return &functions_[it->second];
    }
    return nullptr;
}

const Function* FunctionDetector::find_function(Address entry) const {
    auto it = address_to_function_.find(entry);
    if (it != address_to_function_.end() && it->second < functions_.size()) {
        return &functions_[it->second];
    }
    return nullptr;
}

Function* FunctionDetector::find_function_at(Address addr) {
    for (auto& func : functions_) {
        if (addr >= func.start_address() && addr < func.end_address()) {
            return &func;
        }
    }
    return nullptr;
}

const Function* FunctionDetector::find_function_at(Address addr) const {
    for (const auto& func : functions_) {
        if (addr >= func.start_address() && addr < func.end_address()) {
            return &func;
        }
    }
    return nullptr;
}

void FunctionDetector::add_function(Address entry, const std::string& name) {
    FunctionCandidate candidate;
    candidate.address = entry;
    candidate.source = FunctionSource::UserDefined;
    candidate.name = name;
    candidate.confidence = 100;
    candidates_.push_back(candidate);
}

} // namespace picanha::analysis
