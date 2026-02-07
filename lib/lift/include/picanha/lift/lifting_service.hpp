#pragma once

#include <picanha/lift/lifting_context.hpp>
#include <picanha/lift/lifted_function.hpp>
#include <picanha/lift/ir_optimizer.hpp>
#include <picanha/analysis/function.hpp>
#include <picanha/loader/binary.hpp>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace picanha::lift {

// Result of a lift operation
struct LiftResult {
    bool success{false};
    std::string error;
    std::shared_ptr<LiftedFunction> lifted;
};

// Service for lifting functions to LLVM IR
// This is the main entry point for lifting functionality
class LiftingService {
public:
    explicit LiftingService(std::shared_ptr<loader::Binary> binary);
    ~LiftingService();

    // Non-copyable, non-movable
    LiftingService(const LiftingService&) = delete;
    LiftingService& operator=(const LiftingService&) = delete;

    // Initialize the lifting context
    // Must be called before any lifting operations
    [[nodiscard]] bool initialize();

    // Check if service is ready
    [[nodiscard]] bool is_initialized() const noexcept { return initialized_; }

    // Synchronous lifting (blocks caller)
    [[nodiscard]] LiftResult lift_function(const analysis::Function& func);

    // Asynchronous lifting (returns immediately)
    [[nodiscard]] std::future<LiftResult> lift_function_async(const analysis::Function& func);

    // Lift by address (must find function first)
    [[nodiscard]] LiftResult lift_address(Address entry);
    [[nodiscard]] std::future<LiftResult> lift_address_async(Address entry);

    // Optimization
    [[nodiscard]] bool optimize(LiftedFunction& lifted, OptimizationLevel level);
    [[nodiscard]] std::future<bool> optimize_async(
        std::shared_ptr<LiftedFunction> lifted,
        OptimizationLevel level
    );

    // Cache management
    [[nodiscard]] std::shared_ptr<LiftedFunction> get_cached(FunctionId id) const;
    [[nodiscard]] std::shared_ptr<LiftedFunction> get_cached_by_address(Address addr) const;
    void clear_cache();
    void clear_cache(FunctionId id);
    [[nodiscard]] std::size_t cached_count() const;

    // Callback for lift completion (called on completion thread)
    using LiftCallback = std::function<void(FunctionId, LiftResult)>;
    void set_lift_callback(LiftCallback cb) { lift_callback_ = std::move(cb); }

    // Access underlying components
    [[nodiscard]] LiftingContext* context() noexcept { return context_.get(); }
    [[nodiscard]] const LiftingContext* context() const noexcept { return context_.get(); }
    [[nodiscard]] IROptimizer* optimizer() noexcept { return optimizer_.get(); }

    // Error message if initialization failed
    [[nodiscard]] const std::string& error_message() const noexcept { return error_; }

private:
    LiftResult lift_function_impl(const analysis::Function& func);
    void cache_result(const LiftResult& result);

    std::shared_ptr<loader::Binary> binary_;
    std::unique_ptr<LiftingContext> context_;
    std::unique_ptr<IROptimizer> optimizer_;

    // Cache of lifted functions
    mutable std::mutex cache_mutex_;
    std::unordered_map<FunctionId, std::shared_ptr<LiftedFunction>> cache_;
    std::unordered_map<Address, FunctionId> address_to_id_;

    LiftCallback lift_callback_;
    bool initialized_{false};
    std::string error_;
};

} // namespace picanha::lift
