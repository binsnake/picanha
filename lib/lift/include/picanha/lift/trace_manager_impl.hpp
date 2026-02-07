#pragma once

#include <picanha/loader/binary.hpp>
#include <remill/BC/TraceLifter.h>
#include <memory>
#include <string>
#include <unordered_map>

namespace picanha::lift {

// Implementation of remill::TraceManager for picanha binaries
// This class provides the interface between remill's lifter and picanha's binary loader
class PicanhaTraceManager : public remill::TraceManager {
public:
    explicit PicanhaTraceManager(std::shared_ptr<loader::Binary> binary);
    ~PicanhaTraceManager() override;

    // TraceManager interface implementation

    // Get a name for a trace starting at the given address
    std::string TraceName(std::uint64_t addr) override;

    // Called when a trace has been lifted and defined
    void SetLiftedTraceDefinition(std::uint64_t addr, llvm::Function* func) override;

    // Get a declaration for a trace (forward reference)
    llvm::Function* GetLiftedTraceDeclaration(std::uint64_t addr) override;

    // Get the definition of a lifted trace (nullptr if not yet lifted)
    llvm::Function* GetLiftedTraceDefinition(std::uint64_t addr) override;

    // Try to read an executable byte from the binary
    bool TryReadExecutableByte(std::uint64_t addr, std::uint8_t* byte) override;

    // Additional methods for picanha integration

    // Get all lifted traces
    [[nodiscard]] const std::unordered_map<std::uint64_t, llvm::Function*>&
    lifted_traces() const noexcept {
        return lifted_traces_;
    }

    // Get declared (but not yet defined) traces
    [[nodiscard]] const std::unordered_map<std::uint64_t, llvm::Function*>&
    declared_traces() const noexcept {
        return declared_traces_;
    }

    // Check if an address is executable in the binary
    [[nodiscard]] bool is_executable(std::uint64_t addr) const;

    // Get the underlying binary
    [[nodiscard]] std::shared_ptr<loader::Binary> binary() const noexcept {
        return binary_;
    }

    // Clear all traces (for reuse)
    void clear();

private:
    std::shared_ptr<loader::Binary> binary_;
    std::unordered_map<std::uint64_t, llvm::Function*> lifted_traces_;
    std::unordered_map<std::uint64_t, llvm::Function*> declared_traces_;
};

} // namespace picanha::lift
