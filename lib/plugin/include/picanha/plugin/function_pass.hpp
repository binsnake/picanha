#pragma once

#include "picanha/plugin/plugin.hpp"
#include <picanha/analysis/function.hpp>
#include <picanha/analysis/cfg.hpp>
#include <picanha/analysis/xref_manager.hpp>
#include <picanha/analysis/symbol_table.hpp>
#include <picanha/loader/binary.hpp>
#include <memory>
#include <vector>
#include <string>

namespace picanha::plugin {

// Result of running a function pass
struct FunctionPassResult {
    bool success{true};
    bool modified{false};          // Did the pass modify the function?
    std::string error_message;
    std::vector<std::string> warnings;

    // Statistics
    std::size_t items_processed{0};
    std::size_t items_modified{0};

    static FunctionPassResult ok(bool modified = false) {
        FunctionPassResult r;
        r.success = true;
        r.modified = modified;
        return r;
    }

    static FunctionPassResult error(std::string message) {
        FunctionPassResult r;
        r.success = false;
        r.error_message = std::move(message);
        return r;
    }
};

// Context provided to function passes
class FunctionPassContext {
public:
    virtual ~FunctionPassContext() = default;

    // Access to the binary
    [[nodiscard]] virtual const loader::Binary& binary() const = 0;
    [[nodiscard]] virtual std::shared_ptr<loader::Binary> binary_ptr() const = 0;

    // Access to analysis results
    [[nodiscard]] virtual analysis::XRefManager& xrefs() = 0;
    [[nodiscard]] virtual const analysis::XRefManager& xrefs() const = 0;

    [[nodiscard]] virtual analysis::SymbolTable& symbols() = 0;
    [[nodiscard]] virtual const analysis::SymbolTable& symbols() const = 0;

    // Access to all functions
    [[nodiscard]] virtual std::vector<analysis::Function*> get_functions() = 0;
    [[nodiscard]] virtual analysis::Function* get_function(FunctionId id) = 0;

    // Memory access
    [[nodiscard]] virtual std::optional<std::vector<std::uint8_t>>
    read_memory(Address addr, Size size) const = 0;

    // Logging (inherited from PluginContext)
    virtual void log_info(const char* message) = 0;
    virtual void log_warning(const char* message) = 0;
    virtual void log_error(const char* message) = 0;

    // Progress
    virtual void report_progress(float progress, const char* status) = 0;
    [[nodiscard]] virtual bool is_cancelled() const = 0;
};

// Function pass interface
class IFunctionPass : public IPlugin {
public:
    // Run pass on a single function
    [[nodiscard]] virtual FunctionPassResult run_on_function(
        analysis::Function& function,
        FunctionPassContext& context
    ) = 0;

    // Run pass on all functions (default implementation calls run_on_function)
    [[nodiscard]] virtual FunctionPassResult run_on_all(
        FunctionPassContext& context
    );

    // Optional: Initialize before running on functions
    virtual void begin_pass(FunctionPassContext& context) {}

    // Optional: Finalize after running on all functions
    virtual void end_pass(FunctionPassContext& context) {}

    // Get pass dependencies (other passes that must run first)
    [[nodiscard]] virtual std::vector<std::string> dependencies() const {
        return {};
    }

    // Get pass priority (higher = runs first among same-level passes)
    [[nodiscard]] virtual int priority() const { return 0; }
};

// Default implementation of run_on_all
inline FunctionPassResult IFunctionPass::run_on_all(FunctionPassContext& context) {
    FunctionPassResult total_result;
    total_result.success = true;

    begin_pass(context);

    auto functions = context.get_functions();
    std::size_t count = functions.size();
    std::size_t processed = 0;

    for (auto* func : functions) {
        if (context.is_cancelled()) {
            total_result.success = false;
            total_result.error_message = "Cancelled";
            break;
        }

        auto result = run_on_function(*func, context);

        if (!result.success) {
            total_result.success = false;
            total_result.error_message = result.error_message;
            break;
        }

        if (result.modified) {
            total_result.modified = true;
            total_result.items_modified++;
        }

        total_result.items_processed++;
        processed++;

        context.report_progress(
            static_cast<float>(processed) / static_cast<float>(count),
            "Processing functions..."
        );
    }

    end_pass(context);

    return total_result;
}

// Base class for easier function pass implementation
class FunctionPassBase : public IFunctionPass {
public:
    explicit FunctionPassBase(PluginInfo info) : info_(std::move(info)) {
        info_.type = PluginType::FunctionPass;
    }

    [[nodiscard]] const PluginInfo& info() const override { return info_; }

    bool initialize(PluginContext* context) override {
        context_ = context;
        initialized_ = true;
        return true;
    }

    void shutdown() override {
        initialized_ = false;
        context_ = nullptr;
    }

    [[nodiscard]] bool is_initialized() const override { return initialized_; }

protected:
    [[nodiscard]] PluginContext* context() const { return context_; }

private:
    PluginInfo info_;
    PluginContext* context_{nullptr};
    bool initialized_{false};
};

} // namespace picanha::plugin
