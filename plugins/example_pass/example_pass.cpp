// Example plugin - Function analysis pass
// Demonstrates how to create a plugin for Picanha

#include <picanha/plugin/plugin.hpp>
#include <picanha/plugin/function_pass.hpp>
#include <picanha/analysis/function.hpp>
#include <picanha/analysis/cfg.hpp>
#include <picanha/analysis/basic_block.hpp>

#include <spdlog/spdlog.h>
#include <format>
#include <unordered_set>

namespace {

using namespace picanha;
using namespace picanha::plugin;

// Example pass that identifies and renames common function patterns
class FunctionPatternPass : public IFunctionPass {
public:
    std::string name() const override {
        return "Function Pattern Detector";
    }

    std::string description() const override {
        return "Identifies common function patterns and suggests names";
    }

    PassResult run_on_function(
        analysis::Function& func,
        const analysis::CFG& cfg,
        PluginContext& ctx
    ) override {
        PassResult result;

        // Analyze function characteristics
        auto entry_block = cfg.entry_block();
        if (!entry_block) {
            return result;
        }

        // Check for common patterns

        // 1. Thunk functions (single jump)
        if (is_thunk(func, cfg)) {
            result.suggested_name = detect_thunk_target(func, cfg);
            result.modified = true;
            ctx.log(std::format("Detected thunk: {} -> {}",
                func.name(), result.suggested_name));
            return result;
        }

        // 2. Wrapper functions (prologue, single call, epilogue)
        if (is_wrapper(func, cfg)) {
            result.annotations.push_back("wrapper");
            result.modified = true;
            ctx.log(std::format("Detected wrapper function at 0x{:X}", func.entry_point()));
        }

        // 3. Leaf functions (no calls)
        if (is_leaf(func, cfg)) {
            result.annotations.push_back("leaf");
        }

        // 4. Recursive functions
        if (is_recursive(func, cfg)) {
            result.annotations.push_back("recursive");
            ctx.log(std::format("Detected recursive function at 0x{:X}", func.entry_point()));
        }

        // 5. Check for known patterns
        auto pattern_name = detect_known_pattern(func, cfg);
        if (!pattern_name.empty()) {
            result.suggested_name = pattern_name;
            result.modified = true;
        }

        return result;
    }

private:
    bool is_thunk(const analysis::Function& func, const analysis::CFG& cfg) const {
        // Thunk: single block with just an unconditional jump
        if (cfg.block_count() != 1) return false;

        auto entry = cfg.entry_block();
        if (!entry) return false;

        // Check if it's just a jump
        return entry->instruction_count() == 1 && entry->has_indirect();
    }

    std::string detect_thunk_target(const analysis::Function& func, const analysis::CFG& cfg) const {
        // In a real implementation, would analyze the jump target
        return std::format("thunk_{:X}", func.entry_point());
    }

    bool is_wrapper(const analysis::Function& func, const analysis::CFG& cfg) const {
        // Wrapper: small function that just calls another function
        if (cfg.block_count() > 2) return false;

        auto entry = cfg.entry_block();
        if (!entry) return false;

        // Check for exactly one call
        return entry->has_call() && entry->instruction_count() <= 5;
    }

    bool is_leaf(const analysis::Function& func, const analysis::CFG& cfg) const {
        // Leaf: no call instructions
        for (const auto& block : cfg.blocks()) {
            if (block->has_call()) return false;
        }
        return true;
    }

    bool is_recursive(const analysis::Function& func, const analysis::CFG& cfg) const {
        // Check if any block calls the function's entry point
        // In a real implementation, would check call targets
        return false;
    }

    std::string detect_known_pattern(const analysis::Function& func, const analysis::CFG& cfg) const {
        // Check for known patterns based on function structure

        // Empty function (just ret)
        if (cfg.block_count() == 1) {
            auto entry = cfg.entry_block();
            if (entry && entry->instruction_count() == 1) {
                return "nullsub";
            }
        }

        // In a real implementation, would check for:
        // - String functions (strlen, strcmp, etc.)
        // - Memory functions (memcpy, memset, etc.)
        // - Math functions
        // - Known library patterns

        return "";
    }
};

// Plugin implementation
class ExamplePlugin : public IPlugin {
public:
    PluginInfo info() const override {
        return PluginInfo{
            .name = "Example Analysis Plugin",
            .version = "1.0.0",
            .author = "Picanha Team",
            .description = "Example plugin demonstrating function analysis passes",
            .type = PluginType::Analysis,
        };
    }

    bool initialize(PluginContext& ctx) override {
        ctx.log("Example plugin initialized");
        pass_ = std::make_unique<FunctionPatternPass>();
        return true;
    }

    void shutdown() override {
        pass_.reset();
    }

    std::vector<IFunctionPass*> get_passes() override {
        if (pass_) {
            return {pass_.get()};
        }
        return {};
    }

private:
    std::unique_ptr<FunctionPatternPass> pass_;
};

} // anonymous namespace

// Plugin entry point
PICANHA_PLUGIN_ENTRY(ExamplePlugin)
