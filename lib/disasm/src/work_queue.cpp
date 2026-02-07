#include "picanha/disasm/work_queue.hpp"

namespace picanha::disasm {

void DisasmWorkQueue::push(DisasmWorkItem item) {
    if (item.is_valid()) {
        queue_.push(std::move(item));
    }
}

void DisasmWorkQueue::push(Address addr, WorkPriority priority) {
    DisasmWorkItem item;
    item.address = addr;
    item.priority = priority;
    push(std::move(item));
}

void DisasmWorkQueue::push_function(Address addr) {
    DisasmWorkItem item;
    item.address = addr;
    item.priority = WorkPriority::High;
    item.is_function_entry = true;
    push(std::move(item));
}

bool DisasmWorkQueue::try_pop(DisasmWorkItem& item) {
    return queue_.try_pop(item);
}

bool DisasmWorkQueue::empty() const {
    return queue_.empty();
}

std::size_t DisasmWorkQueue::size() const {
    // Note: concurrent_queue doesn't have size(), this is approximate
    std::size_t count = 0;
    // We can't easily get the size, so return 0 if empty
    return queue_.empty() ? 0 : 1; // Approximate
}

bool DisasmWorkQueue::is_complete() const {
    return queue_.empty() && in_flight_.load(std::memory_order_relaxed) == 0;
}

} // namespace picanha::disasm
