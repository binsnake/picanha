#pragma once

#include "picanha/analysis/xref.hpp"
#include "picanha/analysis/function.hpp"
#include <picanha/core/types.hpp>
#include <picanha/core/parallel.hpp>
#include <picanha/loader/binary.hpp>
#include <picanha/disasm/disassembly_context.hpp>
#include <memory>
#include <vector>
#include <functional>
#include <map>

namespace picanha::analysis {

// Configuration for xref analysis
struct XRefConfig {
    bool track_code_refs{true};
    bool track_data_refs{true};
    bool track_string_refs{true};
    bool resolve_indirect{false};   // Try to resolve indirect refs
    bool include_external{true};    // Include external/import refs
};

// XRef analysis progress callback
using XRefProgressCallback = std::function<void(std::size_t current, std::size_t total)>;

// Cross-reference manager
class XRefManager {
public:
    XRefManager();
    explicit XRefManager(const XRefConfig& config);

    // Build xrefs from functions
    void build_from_functions(const std::vector<Function>& functions);

    // Build xrefs from disassembly context
    void build_from_context(
        std::shared_ptr<disasm::DisassemblyContext> context,
        std::shared_ptr<loader::Binary> binary
    );

    // Build with progress callback
    void build_from_functions(
        const std::vector<Function>& functions,
        XRefProgressCallback callback
    );

    // Add a single xref
    void add(const XRef& xref);
    void add(Address from, Address to, XRefType type);

    // Remove xrefs
    void remove(Address from, Address to);
    void remove_from(Address from);
    void remove_to(Address to);
    void clear();

    // Query xrefs
    [[nodiscard]] std::vector<XRef> get_refs_from(Address addr) const;
    [[nodiscard]] std::vector<XRef> get_refs_to(Address addr) const;
    [[nodiscard]] XRefQueryResult get_refs(Address addr) const;

    // Query by type
    [[nodiscard]] std::vector<XRef> get_refs_from(Address addr, XRefType type) const;
    [[nodiscard]] std::vector<XRef> get_refs_to(Address addr, XRefType type) const;

    // Query code refs
    [[nodiscard]] std::vector<XRef> get_code_refs_from(Address addr) const;
    [[nodiscard]] std::vector<XRef> get_code_refs_to(Address addr) const;

    // Query data refs
    [[nodiscard]] std::vector<XRef> get_data_refs_from(Address addr) const;
    [[nodiscard]] std::vector<XRef> get_data_refs_to(Address addr) const;

    // Query call refs
    [[nodiscard]] std::vector<XRef> get_callers(Address func_addr) const;
    [[nodiscard]] std::vector<XRef> get_callees(Address func_addr) const;

    // Check if address has refs
    [[nodiscard]] bool has_refs_from(Address addr) const;
    [[nodiscard]] bool has_refs_to(Address addr) const;
    [[nodiscard]] bool has_refs(Address addr) const;

    // Statistics
    [[nodiscard]] std::size_t count() const;
    [[nodiscard]] std::size_t count_code_refs() const;
    [[nodiscard]] std::size_t count_data_refs() const;
    [[nodiscard]] std::size_t count_refs_from(Address addr) const;
    [[nodiscard]] std::size_t count_refs_to(Address addr) const;

    // Iteration
    using XRefVisitor = std::function<void(const XRef&)>;
    void for_each(XRefVisitor visitor) const;
    void for_each_from(Address addr, XRefVisitor visitor) const;
    void for_each_to(Address addr, XRefVisitor visitor) const;

    // Get all xrefs
    [[nodiscard]] const std::vector<XRef>& all() const { return xrefs_; }

    // Serialization support
    [[nodiscard]] std::vector<XRef>& mutable_all() { return xrefs_; }

private:
    // Rebuild indices after bulk operations
    void rebuild_indices();

    // Add xref to indices
    void index_xref(std::size_t idx);

    XRefConfig config_;
    std::vector<XRef> xrefs_;

    // Indices for fast lookup
    // Maps address -> indices into xrefs_
    std::map<Address, std::vector<std::size_t>> from_index_;
    std::map<Address, std::vector<std::size_t>> to_index_;

    mutable bool indices_dirty_{false};
};

} // namespace picanha::analysis
