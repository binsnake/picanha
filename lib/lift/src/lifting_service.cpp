#include <picanha/lift/lifting_service.hpp>
#include <picanha/lift/trace_manager_impl.hpp>

#include <remill/BC/TraceLifter.h>
#include <remill/BC/Util.h>

#include <llvm/IR/Module.h>
#include <llvm/Transforms/Utils/Cloning.h>

#include <format>

namespace picanha::lift {

LiftingService::LiftingService(std::shared_ptr<loader::Binary> binary)
    : binary_(std::move(binary))
    , context_(std::make_unique<LiftingContext>())
{
}

LiftingService::~LiftingService() = default;

bool LiftingService::initialize() {
    if (initialized_) {
        return true;
    }

    // Initialize for x86-64 Windows (TODO: detect from binary)
    if (!context_->initialize_x86_64_windows()) {
        error_ = "Failed to initialize lifting context: " + context_->error_message();
        return false;
    }

    // Create the optimizer
    optimizer_ = std::make_unique<IROptimizer>(context_->arch());

    initialized_ = true;
    return true;
}

LiftResult LiftingService::lift_function(const analysis::Function& func) {
    return lift_function_impl(func);
}

std::future<LiftResult> LiftingService::lift_function_async(const analysis::Function& func) {
    // Capture what we need by value for the async task
    FunctionId id = func.id();
    Address entry = func.entry_address();
    std::string name = func.name();

    return std::async(std::launch::async, [this, id, entry, name]() {
        // Create a minimal function object for lifting
        analysis::Function temp_func(id, entry);
        temp_func.set_name(name);

        auto result = lift_function_impl(temp_func);

        // Call the callback if set
        if (lift_callback_) {
            lift_callback_(id, result);
        }

        return result;
    });
}

LiftResult LiftingService::lift_address(Address entry) {
    // Check cache first
    {
        std::lock_guard lock(cache_mutex_);
        auto it = address_to_id_.find(entry);
        if (it != address_to_id_.end()) {
            auto cached = cache_.find(it->second);
            if (cached != cache_.end()) {
                return LiftResult{true, "", cached->second};
            }
        }
    }

    // Create a temporary function for lifting
    FunctionId temp_id{static_cast<std::uint32_t>(entry & 0xFFFFFFFF)};
    analysis::Function temp_func(temp_id, entry);
    temp_func.set_name(std::format("sub_{:X}", entry));

    return lift_function_impl(temp_func);
}

std::future<LiftResult> LiftingService::lift_address_async(Address entry) {
    return std::async(std::launch::async, [this, entry]() {
        return lift_address(entry);
    });
}

LiftResult LiftingService::lift_function_impl(const analysis::Function& func) {
    if (!initialized_) {
        return LiftResult{false, "Lifting service not initialized", nullptr};
    }

    // Check cache
    {
        std::lock_guard lock(cache_mutex_);
        auto it = cache_.find(func.id());
        if (it != cache_.end()) {
            return LiftResult{true, "", it->second};
        }
    }

    try {
        // Lock the context for thread safety
        auto ctx_lock = context_->lock();

        // Create trace manager for reading bytes from the binary
        auto trace_manager = std::make_unique<PicanhaTraceManager>(binary_);

        // Create the lifted function object
        auto lifted = std::make_shared<LiftedFunction>(
            func.id(),
            func.entry_address(),
            func.name()
        );
        lifted->set_status(LiftStatus::Lifting);

        // Create the trace lifter
        remill::TraceLifter lifter(context_->arch(), *trace_manager);

        // Lift the function starting at the entry address
        llvm::Function* lifted_func = nullptr;
        bool lift_success = lifter.Lift(func.entry_address(),
            [&lifted_func](uint64_t addr, llvm::Function* fn) {
                lifted_func = fn;
            });

        if (!lifted_func) {
            lifted->set_error("Failed to lift function at " +
                              std::format("0x{:X}", func.entry_address()));
            return LiftResult{false, lifted->error_message(), lifted};
        }

        // The lifted function is in the semantics module, not our empty module
        // Clone the semantics module to get the function and its dependencies
        llvm::Module* parent_module = lifted_func->getParent();
        if (!parent_module) {
            lifted->set_error("Lifted function has no parent module");
            return LiftResult{false, lifted->error_message(), lifted};
        }

        // Clone the module to get an independent copy we can modify
        auto cloned_module = llvm::CloneModule(*parent_module);
        if (!cloned_module) {
            lifted->set_error("Failed to clone module");
            return LiftResult{false, lifted->error_message(), lifted};
        }

        // Find the cloned function in the new module
        llvm::Function* cloned_func = cloned_module->getFunction(lifted_func->getName());

        // Store the cloned module and function in the lifted object
        lifted->set_function(cloned_func);
        lifted->set_module(std::move(cloned_module));
        lifted->set_status(LiftStatus::Lifted);

        // Cache the result
        cache_result(LiftResult{true, "", lifted});

        return LiftResult{true, "", lifted};

    } catch (const std::exception& e) {
        return LiftResult{false, std::string("Exception during lifting: ") + e.what(), nullptr};
    }
}

bool LiftingService::optimize(LiftedFunction& lifted, OptimizationLevel level) {
    if (!optimizer_) {
        return false;
    }

    // Lock context during optimization
    auto ctx_lock = context_->lock();

    lifted.set_status(LiftStatus::Optimizing);
    bool success = optimizer_->optimize(lifted, level);

    if (success) {
        lifted.set_status(LiftStatus::Ready);
    } else {
        lifted.set_status(LiftStatus::Error);
        lifted.set_error("Optimization failed");
    }

    return success;
}

std::future<bool> LiftingService::optimize_async(
    std::shared_ptr<LiftedFunction> lifted,
    OptimizationLevel level
) {
    return std::async(std::launch::async, [this, lifted, level]() {
        return optimize(*lifted, level);
    });
}

std::shared_ptr<LiftedFunction> LiftingService::get_cached(FunctionId id) const {
    std::lock_guard lock(cache_mutex_);
    auto it = cache_.find(id);
    if (it != cache_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<LiftedFunction> LiftingService::get_cached_by_address(Address addr) const {
    std::lock_guard lock(cache_mutex_);
    auto it = address_to_id_.find(addr);
    if (it == address_to_id_.end()) {
        return nullptr;
    }
    auto cache_it = cache_.find(it->second);
    if (cache_it != cache_.end()) {
        return cache_it->second;
    }
    return nullptr;
}

void LiftingService::clear_cache() {
    std::lock_guard lock(cache_mutex_);
    cache_.clear();
    address_to_id_.clear();
}

void LiftingService::clear_cache(FunctionId id) {
    std::lock_guard lock(cache_mutex_);
    auto it = cache_.find(id);
    if (it != cache_.end()) {
        // Remove from address map too
        Address addr = it->second->entry_address();
        address_to_id_.erase(addr);
        cache_.erase(it);
    }
}

std::size_t LiftingService::cached_count() const {
    std::lock_guard lock(cache_mutex_);
    return cache_.size();
}

void LiftingService::cache_result(const LiftResult& result) {
    if (!result.success || !result.lifted) {
        return;
    }

    std::lock_guard lock(cache_mutex_);
    cache_[result.lifted->id()] = result.lifted;
    address_to_id_[result.lifted->entry_address()] = result.lifted->id();
}

} // namespace picanha::lift
