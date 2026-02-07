#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <vector>
#include <new>
#include <type_traits>

namespace picanha {

// Simple arena allocator for bulk allocations during analysis
// All allocations are freed together when the arena is destroyed
class Arena {
public:
    static constexpr std::size_t DEFAULT_BLOCK_SIZE = 64 * 1024; // 64KB blocks

    explicit Arena(std::size_t block_size = DEFAULT_BLOCK_SIZE) noexcept
        : block_size_(block_size)
        , current_block_(nullptr)
        , current_pos_(0)
        , current_end_(0)
    {}

    ~Arena() = default;

    // Non-copyable, movable
    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;
    Arena(Arena&&) = default;
    Arena& operator=(Arena&&) = default;

    // Allocate raw memory with alignment
    [[nodiscard]] void* allocate(std::size_t size, std::size_t alignment = alignof(std::max_align_t)) {
        // Align the current position
        std::size_t aligned_pos = (current_pos_ + alignment - 1) & ~(alignment - 1);
        std::size_t new_pos = aligned_pos + size;

        if (new_pos > current_end_) {
            // Need a new block
            allocate_block(std::max(size + alignment, block_size_));
            aligned_pos = (current_pos_ + alignment - 1) & ~(alignment - 1);
            new_pos = aligned_pos + size;
        }

        void* ptr = current_block_ + aligned_pos;
        current_pos_ = new_pos;
        total_allocated_ += size;
        return ptr;
    }

    // Allocate and construct an object
    template<typename T, typename... Args>
    [[nodiscard]] T* create(Args&&... args) {
        void* ptr = allocate(sizeof(T), alignof(T));
        return new (ptr) T(std::forward<Args>(args)...);
    }

    // Allocate an array of objects (default constructed)
    template<typename T>
    [[nodiscard]] T* create_array(std::size_t count) {
        void* ptr = allocate(sizeof(T) * count, alignof(T));
        T* arr = static_cast<T*>(ptr);

        if constexpr (!std::is_trivially_default_constructible_v<T>) {
            for (std::size_t i = 0; i < count; ++i) {
                new (&arr[i]) T();
            }
        }

        return arr;
    }

    // Reset the arena (keeps memory, allows reuse)
    void reset() noexcept {
        if (!blocks_.empty()) {
            current_block_ = blocks_[0].get();
            current_pos_ = 0;
            current_end_ = block_size_;
        }
        total_allocated_ = 0;
    }

    // Release all memory
    void clear() noexcept {
        blocks_.clear();
        current_block_ = nullptr;
        current_pos_ = 0;
        current_end_ = 0;
        total_allocated_ = 0;
    }

    // Statistics
    [[nodiscard]] std::size_t total_allocated() const noexcept { return total_allocated_; }
    [[nodiscard]] std::size_t block_count() const noexcept { return blocks_.size(); }
    [[nodiscard]] std::size_t memory_used() const noexcept {
        return blocks_.size() * block_size_;
    }

private:
    void allocate_block(std::size_t min_size) {
        std::size_t size = std::max(min_size, block_size_);
        auto block = std::make_unique<std::uint8_t[]>(size);
        current_block_ = block.get();
        current_pos_ = 0;
        current_end_ = size;
        blocks_.push_back(std::move(block));
    }

    std::size_t block_size_;
    std::vector<std::unique_ptr<std::uint8_t[]>> blocks_;
    std::uint8_t* current_block_;
    std::size_t current_pos_;
    std::size_t current_end_;
    std::size_t total_allocated_{0};
};

// STL-compatible allocator backed by an arena
template<typename T>
class ArenaAllocator {
public:
    using value_type = T;

    explicit ArenaAllocator(Arena& arena) noexcept : arena_(&arena) {}

    template<typename U>
    ArenaAllocator(const ArenaAllocator<U>& other) noexcept : arena_(other.arena_) {}

    [[nodiscard]] T* allocate(std::size_t n) {
        return static_cast<T*>(arena_->allocate(n * sizeof(T), alignof(T)));
    }

    void deallocate(T*, std::size_t) noexcept {
        // Arena doesn't support individual deallocation
    }

    template<typename U>
    bool operator==(const ArenaAllocator<U>& other) const noexcept {
        return arena_ == other.arena_;
    }

private:
    template<typename U>
    friend class ArenaAllocator;

    Arena* arena_;
};

} // namespace picanha
