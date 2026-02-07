#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/parallel.hpp>
#include <tbb/concurrent_queue.h>
#include <atomic>
#include <functional>

namespace picanha::disasm {

// Work item priority
enum class WorkPriority : std::uint8_t {
    High,       // Entry points, explicit function starts
    Normal,     // Call targets
    Low,        // Jump targets, speculative
};

// Work item for disassembly
struct DisasmWorkItem {
    Address address{INVALID_ADDRESS};
    WorkPriority priority{WorkPriority::Normal};
    FunctionId source_function{INVALID_FUNCTION_ID};  // Where this came from
    bool is_function_entry{false};

    [[nodiscard]] bool is_valid() const noexcept {
        return address != INVALID_ADDRESS;
    }

    // Comparison for priority queue (higher priority = smaller value)
    [[nodiscard]] bool operator<(const DisasmWorkItem& other) const noexcept {
        return static_cast<std::uint8_t>(priority) > static_cast<std::uint8_t>(other.priority);
    }
};

// Thread-safe work queue for parallel disassembly
class DisasmWorkQueue {
public:
    DisasmWorkQueue() = default;

    // Add work item
    void push(DisasmWorkItem item);
    void push(Address addr, WorkPriority priority = WorkPriority::Normal);
    void push_function(Address addr);  // Convenience for function entries

    // Get work item (blocks if empty)
    [[nodiscard]] bool try_pop(DisasmWorkItem& item);

    // Check if queue is empty
    [[nodiscard]] bool empty() const;

    // Get approximate size
    [[nodiscard]] std::size_t size() const;

    // Get number of items processed
    [[nodiscard]] std::size_t processed_count() const noexcept {
        return processed_.load(std::memory_order_relaxed);
    }

    // Increment processed counter
    void mark_processed() noexcept {
        processed_.fetch_add(1, std::memory_order_relaxed);
    }

    // Check if all work is done (empty queue + no in-flight items)
    [[nodiscard]] bool is_complete() const;

    // Increment/decrement in-flight counter
    void begin_work() noexcept {
        in_flight_.fetch_add(1, std::memory_order_relaxed);
    }

    void end_work() noexcept {
        in_flight_.fetch_sub(1, std::memory_order_relaxed);
    }

private:
    tbb::concurrent_queue<DisasmWorkItem> queue_;
    std::atomic<std::size_t> processed_{0};
    std::atomic<std::size_t> in_flight_{0};
};

// RAII guard for in-flight work
class WorkGuard {
public:
    explicit WorkGuard(DisasmWorkQueue& queue) : queue_(queue) {
        queue_.begin_work();
    }

    ~WorkGuard() {
        queue_.end_work();
    }

    WorkGuard(const WorkGuard&) = delete;
    WorkGuard& operator=(const WorkGuard&) = delete;

private:
    DisasmWorkQueue& queue_;
};

} // namespace picanha::disasm
