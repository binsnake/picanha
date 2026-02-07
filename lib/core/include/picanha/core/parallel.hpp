#pragma once

// Qt defines 'emit' as a macro which conflicts with TBB's event::emit method
// Undefine the macro before including TBB headers, restore it afterwards
#ifdef emit
#define _PICANHA_QT_EMIT_WAS_DEFINED
#undef emit
#endif

#include <tbb/tbb.h>
#include <tbb/concurrent_vector.h>
#include <tbb/concurrent_unordered_map.h>
#include <tbb/concurrent_unordered_set.h>
#include <tbb/concurrent_queue.h>
#include <tbb/parallel_for.h>
#include <tbb/parallel_for_each.h>
#include <tbb/task_group.h>
#include <tbb/enumerable_thread_specific.h>
#include <tbb/spin_mutex.h>
#include <tbb/spin_rw_mutex.h>

// Restore Qt's emit macro if it was defined before
#ifdef _PICANHA_QT_EMIT_WAS_DEFINED
#undef _PICANHA_QT_EMIT_WAS_DEFINED
#define emit
#endif

#include <functional>
#include <atomic>
#include <optional>

namespace picanha {

// Concurrent container aliases
template<typename T>
using ConcurrentVector = tbb::concurrent_vector<T>;

template<typename K, typename V, typename Hash = std::hash<K>, typename Equal = std::equal_to<K>>
using ConcurrentMap = tbb::concurrent_unordered_map<K, V, Hash, Equal>;

template<typename T, typename Hash = std::hash<T>, typename Equal = std::equal_to<T>>
using ConcurrentSet = tbb::concurrent_unordered_set<T, Hash, Equal>;

template<typename T>
using ConcurrentQueue = tbb::concurrent_bounded_queue<T>;

// Thread-local storage
template<typename T>
using ThreadLocal = tbb::enumerable_thread_specific<T>;

// Mutex types
using SpinMutex = tbb::spin_mutex;
using SpinRWMutex = tbb::spin_rw_mutex;

// Parallel work queue for analysis tasks
template<typename Task>
class ParallelWorkQueue {
public:
    ParallelWorkQueue() = default;

    // Add a task to the queue
    void push(Task task) {
        queue_.push(std::move(task));
        pending_.fetch_add(1, std::memory_order_relaxed);
    }

    // Process all tasks in parallel
    // Processor should return true if it added new tasks
    template<typename Processor>
    void process_all(Processor&& processor) {
        tbb::task_group group;

        auto worker = [this, &processor, &group]() {
            Task task;
            while (queue_.try_pop(task)) {
                processor(std::move(task));
                pending_.fetch_sub(1, std::memory_order_relaxed);
            }
        };

        // Spawn workers until queue is empty
        while (pending_.load(std::memory_order_relaxed) > 0 || !queue_.empty()) {
            if (!queue_.empty()) {
                group.run(worker);
            }
        }

        group.wait();
    }

    // Check if queue is empty
    [[nodiscard]] bool empty() const {
        return queue_.empty() && pending_.load(std::memory_order_relaxed) == 0;
    }

    [[nodiscard]] std::size_t pending() const {
        return pending_.load(std::memory_order_relaxed);
    }

private:
    tbb::concurrent_queue<Task> queue_;
    std::atomic<std::size_t> pending_{0};
};

// Parallel for with index
template<typename Index, typename Body>
void parallel_for(Index first, Index last, Body&& body) {
    tbb::parallel_for(first, last, std::forward<Body>(body));
}

// Parallel for with range
template<typename Range, typename Body>
void parallel_for_range(const Range& range, Body&& body) {
    tbb::parallel_for(range, std::forward<Body>(body));
}

// Parallel for_each
template<typename Iterator, typename Body>
void parallel_for_each(Iterator first, Iterator last, Body&& body) {
    tbb::parallel_for_each(first, last, std::forward<Body>(body));
}

// Parallel reduce
template<typename Range, typename Value, typename Reduce, typename Combine>
Value parallel_reduce(const Range& range, Value init, Reduce&& reduce, Combine&& combine) {
    return tbb::parallel_reduce(
        range,
        init,
        std::forward<Reduce>(reduce),
        std::forward<Combine>(combine)
    );
}

// Task group for fire-and-forget parallel tasks
class TaskGroup {
public:
    template<typename F>
    void run(F&& f) {
        group_.run(std::forward<F>(f));
    }

    void wait() {
        group_.wait();
    }

    void cancel() {
        group_.cancel();
    }

private:
    tbb::task_group group_;
};

// Scoped parallel region with thread count control
class ParallelScope {
public:
    explicit ParallelScope(int num_threads)
        : arena_(num_threads)
    {}

    template<typename F>
    void execute(F&& f) {
        arena_.execute(std::forward<F>(f));
    }

    [[nodiscard]] int max_concurrency() const {
        return arena_.max_concurrency();
    }

private:
    tbb::task_arena arena_;
};

// Get hardware concurrency
[[nodiscard]] inline int hardware_concurrency() {
    return static_cast<int>(tbb::info::default_concurrency());
}

} // namespace picanha
