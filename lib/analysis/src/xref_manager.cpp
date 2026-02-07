#include "picanha/analysis/xref_manager.hpp"
#include <picanha/disasm/flow_analyzer.hpp>
#include <algorithm>

namespace picanha::analysis {

XRefManager::XRefManager()
    : config_{}
{}

XRefManager::XRefManager(const XRefConfig& config)
    : config_(config)
{}

void XRefManager::build_from_functions(const std::vector<Function>& functions) {
    build_from_functions(functions, nullptr);
}

void XRefManager::build_from_functions(
    const std::vector<Function>& functions,
    XRefProgressCallback callback
) {
    clear();

    std::size_t total = functions.size();
    std::size_t current = 0;

    for (const auto& func : functions) {
        FunctionId func_id = func.id();

        func.cfg().for_each_block([this, func_id](const BasicBlock& block) {
            BlockId block_id = block.id();

            for (const auto& instr : block.instructions()) {
                Address from = instr.ip();

                // Analyze control flow
                auto targets = disasm::FlowAnalyzer::analyze(instr);

                for (const auto& target : targets) {
                    if (!target.is_valid()) {
                        // Indirect reference
                        if (target.is_call && config_.track_code_refs) {
                            XRef xref;
                            xref.from = from;
                            xref.to = INVALID_ADDRESS;
                            xref.type = XRefType::IndirectCall;
                            xref.flow = XRefFlow::Near;
                            xref.from_func = func_id;
                            xref.from_block = block_id;
                            xref.is_indirect = true;
                            add(xref);
                        }
                        continue;
                    }

                    if (!config_.track_code_refs) continue;

                    XRef xref;
                    xref.from = from;
                    xref.to = target.target;
                    xref.from_func = func_id;
                    xref.from_block = block_id;
                    xref.flow = XRefFlow::Near;

                    if (target.is_call) {
                        xref.type = XRefType::Call;
                    } else if (target.is_conditional) {
                        xref.type = XRefType::ConditionalJump;
                        xref.is_conditional = true;
                    } else if (!target.is_fallthrough) {
                        xref.type = XRefType::Jump;
                    } else {
                        continue;  // Skip fallthrough
                    }

                    add(xref);
                }

                // Analyze data references (memory operands)
                if (config_.track_data_refs) {
                    // Check for RIP-relative addressing and other memory refs
                    // This requires deeper instruction analysis

                    // For now, check if instruction accesses memory
                    const auto& raw = instr.raw();

                    for (std::uint32_t op_idx = 0; op_idx < raw.op_count(); ++op_idx) {
                        auto op_kind = raw.op_kind(op_idx);

                        if (op_kind == iced_x86::OpKind::MEMORY) {
                            // Get memory address if it's a displacement-only or RIP-relative
                            auto mem_displ = raw.memory_displacement64();

                            if (mem_displ != 0) {
                                // Check if this looks like a valid address
                                // (simplified check - would need binary info)

                                XRef xref;
                                xref.from = from;
                                xref.to = mem_displ;
                                xref.from_func = func_id;
                                xref.from_block = block_id;
                                xref.flow = XRefFlow::Near;

                                // Determine read/write based on operand position
                                // First operand is typically the destination (write)
                                // Other operands are typically sources (read)
                                if (op_idx == 0 && raw.op_count() > 1) {
                                    xref.type = XRefType::Write;
                                } else {
                                    xref.type = XRefType::Read;
                                }

                                add(xref);
                            }
                        } else if (op_kind == iced_x86::OpKind::IMMEDIATE64 ||
                                   op_kind == iced_x86::OpKind::IMMEDIATE32TO64) {
                            // Could be an address constant (lea, mov, etc.)
                            auto imm = raw.immediate64();

                            // Check if it looks like an address
                            if (imm > 0x10000 && imm < 0x00007FFFFFFFFFFF) {
                                XRef xref;
                                xref.from = from;
                                xref.to = imm;
                                xref.type = XRefType::Offset;
                                xref.from_func = func_id;
                                xref.from_block = block_id;
                                xref.flow = XRefFlow::Near;
                                add(xref);
                            }
                        }
                    }
                }
            }
        });

        if (callback) {
            ++current;
            callback(current, total);
        }
    }

    rebuild_indices();
}

void XRefManager::build_from_context(
    std::shared_ptr<disasm::DisassemblyContext> context,
    std::shared_ptr<loader::Binary> binary
) {
    clear();

    // Build from call targets tracked in context
    context->for_each_call_target([this](Address target) {
        // We only know the target, not the source
        // This is less useful - prefer build_from_functions
    });

    rebuild_indices();
}

void XRefManager::add(const XRef& xref) {
    std::size_t idx = xrefs_.size();
    xrefs_.push_back(xref);
    index_xref(idx);
}

void XRefManager::add(Address from, Address to, XRefType type) {
    XRef xref;
    xref.from = from;
    xref.to = to;
    xref.type = type;
    xref.flow = XRefFlow::Near;
    add(xref);
}

void XRefManager::remove(Address from, Address to) {
    xrefs_.erase(
        std::remove_if(xrefs_.begin(), xrefs_.end(),
            [from, to](const XRef& x) {
                return x.from == from && x.to == to;
            }),
        xrefs_.end()
    );
    indices_dirty_ = true;
}

void XRefManager::remove_from(Address from) {
    xrefs_.erase(
        std::remove_if(xrefs_.begin(), xrefs_.end(),
            [from](const XRef& x) { return x.from == from; }),
        xrefs_.end()
    );
    indices_dirty_ = true;
}

void XRefManager::remove_to(Address to) {
    xrefs_.erase(
        std::remove_if(xrefs_.begin(), xrefs_.end(),
            [to](const XRef& x) { return x.to == to; }),
        xrefs_.end()
    );
    indices_dirty_ = true;
}

void XRefManager::clear() {
    xrefs_.clear();
    from_index_.clear();
    to_index_.clear();
    indices_dirty_ = false;
}

std::vector<XRef> XRefManager::get_refs_from(Address addr) const {
    if (indices_dirty_) {
        const_cast<XRefManager*>(this)->rebuild_indices();
    }

    std::vector<XRef> result;
    auto it = from_index_.find(addr);
    if (it != from_index_.end()) {
        result.reserve(it->second.size());
        for (std::size_t idx : it->second) {
            result.push_back(xrefs_[idx]);
        }
    }
    return result;
}

std::vector<XRef> XRefManager::get_refs_to(Address addr) const {
    if (indices_dirty_) {
        const_cast<XRefManager*>(this)->rebuild_indices();
    }

    std::vector<XRef> result;
    auto it = to_index_.find(addr);
    if (it != to_index_.end()) {
        result.reserve(it->second.size());
        for (std::size_t idx : it->second) {
            result.push_back(xrefs_[idx]);
        }
    }
    return result;
}

XRefQueryResult XRefManager::get_refs(Address addr) const {
    XRefQueryResult result;
    result.refs_from = get_refs_from(addr);
    result.refs_to = get_refs_to(addr);
    return result;
}

std::vector<XRef> XRefManager::get_refs_from(Address addr, XRefType type) const {
    auto refs = get_refs_from(addr);
    refs.erase(
        std::remove_if(refs.begin(), refs.end(),
            [type](const XRef& x) { return x.type != type; }),
        refs.end()
    );
    return refs;
}

std::vector<XRef> XRefManager::get_refs_to(Address addr, XRefType type) const {
    auto refs = get_refs_to(addr);
    refs.erase(
        std::remove_if(refs.begin(), refs.end(),
            [type](const XRef& x) { return x.type != type; }),
        refs.end()
    );
    return refs;
}

std::vector<XRef> XRefManager::get_code_refs_from(Address addr) const {
    auto refs = get_refs_from(addr);
    refs.erase(
        std::remove_if(refs.begin(), refs.end(),
            [](const XRef& x) { return !is_code_xref(x.type); }),
        refs.end()
    );
    return refs;
}

std::vector<XRef> XRefManager::get_code_refs_to(Address addr) const {
    auto refs = get_refs_to(addr);
    refs.erase(
        std::remove_if(refs.begin(), refs.end(),
            [](const XRef& x) { return !is_code_xref(x.type); }),
        refs.end()
    );
    return refs;
}

std::vector<XRef> XRefManager::get_data_refs_from(Address addr) const {
    auto refs = get_refs_from(addr);
    refs.erase(
        std::remove_if(refs.begin(), refs.end(),
            [](const XRef& x) { return !is_data_xref(x.type); }),
        refs.end()
    );
    return refs;
}

std::vector<XRef> XRefManager::get_data_refs_to(Address addr) const {
    auto refs = get_refs_to(addr);
    refs.erase(
        std::remove_if(refs.begin(), refs.end(),
            [](const XRef& x) { return !is_data_xref(x.type); }),
        refs.end()
    );
    return refs;
}

std::vector<XRef> XRefManager::get_callers(Address func_addr) const {
    auto refs = get_refs_to(func_addr);
    refs.erase(
        std::remove_if(refs.begin(), refs.end(),
            [](const XRef& x) { return !is_call_xref(x.type); }),
        refs.end()
    );
    return refs;
}

std::vector<XRef> XRefManager::get_callees(Address func_addr) const {
    // This would need to iterate all refs from the function's address range
    // For now, return refs from the exact address
    auto refs = get_refs_from(func_addr);
    refs.erase(
        std::remove_if(refs.begin(), refs.end(),
            [](const XRef& x) { return !is_call_xref(x.type); }),
        refs.end()
    );
    return refs;
}

bool XRefManager::has_refs_from(Address addr) const {
    if (indices_dirty_) {
        const_cast<XRefManager*>(this)->rebuild_indices();
    }
    return from_index_.find(addr) != from_index_.end();
}

bool XRefManager::has_refs_to(Address addr) const {
    if (indices_dirty_) {
        const_cast<XRefManager*>(this)->rebuild_indices();
    }
    return to_index_.find(addr) != to_index_.end();
}

bool XRefManager::has_refs(Address addr) const {
    return has_refs_from(addr) || has_refs_to(addr);
}

std::size_t XRefManager::count() const {
    return xrefs_.size();
}

std::size_t XRefManager::count_code_refs() const {
    return std::count_if(xrefs_.begin(), xrefs_.end(),
        [](const XRef& x) { return is_code_xref(x.type); });
}

std::size_t XRefManager::count_data_refs() const {
    return std::count_if(xrefs_.begin(), xrefs_.end(),
        [](const XRef& x) { return is_data_xref(x.type); });
}

std::size_t XRefManager::count_refs_from(Address addr) const {
    if (indices_dirty_) {
        const_cast<XRefManager*>(this)->rebuild_indices();
    }
    auto it = from_index_.find(addr);
    return it != from_index_.end() ? it->second.size() : 0;
}

std::size_t XRefManager::count_refs_to(Address addr) const {
    if (indices_dirty_) {
        const_cast<XRefManager*>(this)->rebuild_indices();
    }
    auto it = to_index_.find(addr);
    return it != to_index_.end() ? it->second.size() : 0;
}

void XRefManager::for_each(XRefVisitor visitor) const {
    for (const auto& xref : xrefs_) {
        visitor(xref);
    }
}

void XRefManager::for_each_from(Address addr, XRefVisitor visitor) const {
    for (const auto& xref : get_refs_from(addr)) {
        visitor(xref);
    }
}

void XRefManager::for_each_to(Address addr, XRefVisitor visitor) const {
    for (const auto& xref : get_refs_to(addr)) {
        visitor(xref);
    }
}

void XRefManager::rebuild_indices() {
    from_index_.clear();
    to_index_.clear();

    for (std::size_t i = 0; i < xrefs_.size(); ++i) {
        index_xref(i);
    }

    indices_dirty_ = false;
}

void XRefManager::index_xref(std::size_t idx) {
    const auto& xref = xrefs_[idx];
    from_index_[xref.from].push_back(idx);
    if (xref.to != INVALID_ADDRESS) {
        to_index_[xref.to].push_back(idx);
    }
}

} // namespace picanha::analysis
