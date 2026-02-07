#pragma once

#include "picanha/analysis/function.hpp"
#include "picanha/analysis/cfg_builder.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/parallel.hpp>
#include <picanha/loader/binary.hpp>
#include <picanha/disasm/disassembly_context.hpp>
#include <memory>
#include <vector>
#include <functional>

namespace picanha::analysis {

// Source of function detection
enum class FunctionSource : std::uint8_t {
    ExceptionInfo,      // From PE exception directory (most reliable)
    Export,             // Exported symbol
    Import,             // Import thunk
    CallTarget,         // Target of a call instruction
    JumpTarget,         // Target of unconditional jump (potential thunk)
    ProloguePattern,    // Matched prologue pattern
    Symbol,             // From debug symbols/PDB
    UserDefined,        // Manually specified
    Heuristic,          // Other heuristics
};

// Detected function candidate
struct FunctionCandidate {
    Address address;
    FunctionSource source;
    std::string name;           // If known (from export/import)
    std::uint8_t confidence;    // 0-100

    // Exception info (if from exception directory)
    Address end_address{INVALID_ADDRESS};
    Address unwind_info{INVALID_ADDRESS};
};

// Configuration for function detection
struct FunctionDetectorConfig {
    // Detection sources (reliable)
    bool use_exception_info{true};    // PE64 runtime functions - most reliable
    bool use_exports{true};           // Exported symbols
    bool use_imports{true};           // Import thunks

    // Detection sources (recursive descent)
    bool use_call_targets{true};      // Targets of call instructions

    // Detection sources (linear sweep - less reliable, off by default)
    bool use_prologue_patterns{false}; // Scan for prologue byte patterns
    bool use_heuristics{false};        // Other heuristics

    // Prologue patterns to look for (only if use_prologue_patterns is true)
    bool detect_push_rbp{true};
    bool detect_sub_rsp{true};
    bool detect_mov_rsp{true};

    // Minimum confidence to include
    std::uint8_t min_confidence{50};   // Raised to filter low-quality matches

    // Analysis options
    bool build_cfg{true};
    bool analyze_calls{true};
    std::size_t max_functions{1000000};
};

// Progress callback
using DetectionProgressCallback = std::function<void(std::size_t current, std::size_t total, const char* phase)>;

// Function detection engine
class FunctionDetector {
public:
    explicit FunctionDetector(
        std::shared_ptr<loader::Binary> binary,
        std::shared_ptr<disasm::DisassemblyContext> context,
        const FunctionDetectorConfig& config = {}
    );

    // Run detection
    void detect();

    // Run detection with progress callback
    void detect(DetectionProgressCallback callback);

    // Get detected functions
    [[nodiscard]] const std::vector<Function>& functions() const noexcept { return functions_; }
    [[nodiscard]] std::vector<Function>& functions() noexcept { return functions_; }

    // Move functions out
    [[nodiscard]] std::vector<Function> take_functions() { return std::move(functions_); }

    // Get candidates (before CFG building)
    [[nodiscard]] const std::vector<FunctionCandidate>& candidates() const noexcept { return candidates_; }

    // Find function by address
    [[nodiscard]] Function* find_function(Address entry);
    [[nodiscard]] const Function* find_function(Address entry) const;

    // Find function containing address
    [[nodiscard]] Function* find_function_at(Address addr);
    [[nodiscard]] const Function* find_function_at(Address addr) const;

    // Add manual function
    void add_function(Address entry, const std::string& name = "");

private:
    // Detection phases
    void collect_from_exceptions();
    void collect_from_exports();
    void collect_from_imports();
    void collect_from_call_targets();
    void collect_from_prologue_patterns();
    void collect_from_heuristics();

    // Deduplication and sorting
    void deduplicate_candidates();

    // Build functions from candidates
    void build_functions();
    void build_function_parallel(const FunctionCandidate& candidate, FunctionId id);

    // Analyze inter-function relationships
    void analyze_call_graph();

    // Check for prologue pattern at address
    bool check_prologue(Address addr) const;

    // Helper to check if address is valid code
    bool is_valid_code_address(Address addr) const;

    std::shared_ptr<loader::Binary> binary_;
    std::shared_ptr<disasm::DisassemblyContext> context_;
    FunctionDetectorConfig config_;

    std::vector<FunctionCandidate> candidates_;
    std::vector<Function> functions_;
    ConcurrentMap<Address, FunctionId> address_to_function_;

    DetectionProgressCallback progress_callback_;
    std::atomic<std::size_t> progress_counter_{0};
};

} // namespace picanha::analysis
