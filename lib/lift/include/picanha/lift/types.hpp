#pragma once

#include <cstdint>

namespace picanha::lift {

// Optimization level for lifted IR
enum class OptimizationLevel : std::uint8_t {
    O0 = 0,  // No optimization
    O1 = 1,  // Basic optimizations
    O2 = 2,  // Standard optimizations (default)
    O3 = 3   // Aggressive optimizations
};

// Status of a lifted function
enum class LiftStatus {
    Pending,      // Not yet started
    Lifting,      // Currently lifting
    Lifted,       // Successfully lifted, not optimized
    Optimizing,   // Currently running optimization
    Ready,        // Lifted and ready (optimization complete if requested)
    Error         // Lifting failed
};

// Convert optimization level to string
inline const char* to_string(OptimizationLevel level) {
    switch (level) {
        case OptimizationLevel::O0: return "O0";
        case OptimizationLevel::O1: return "O1";
        case OptimizationLevel::O2: return "O2";
        case OptimizationLevel::O3: return "O3";
    }
    return "Unknown";
}

// Convert lift status to string
inline const char* to_string(LiftStatus status) {
    switch (status) {
        case LiftStatus::Pending: return "Pending";
        case LiftStatus::Lifting: return "Lifting";
        case LiftStatus::Lifted: return "Lifted";
        case LiftStatus::Optimizing: return "Optimizing";
        case LiftStatus::Ready: return "Ready";
        case LiftStatus::Error: return "Error";
    }
    return "Unknown";
}

} // namespace picanha::lift
