#include "picanha/analysis/indirect_resolver.hpp"
#include <algorithm>
#include <cstring>

namespace picanha::analysis {

IndirectCallResolver::IndirectCallResolver(
    std::shared_ptr<loader::Binary> binary,
    const IndirectResolverConfig& config
)
    : binary_(std::move(binary))
    , config_(config)
    , matcher_(builtin_patterns())
{}

IndirectCallInfo IndirectCallResolver::analyze_call(
    const BasicBlock& block,
    Address call_address
) {
    // Find the call instruction
    std::size_t call_index = 0;
    bool found = false;

    const auto& instructions = block.instructions();
    for (std::size_t i = 0; i < instructions.size(); ++i) {
        if (instructions[i].ip() == call_address) {
            call_index = i;
            found = true;
            break;
        }
    }

    if (!found) return {};

    const auto& call_instr = instructions[call_index];
    const auto& underlying = call_instr.raw();

    if (underlying.op_count() < 1) return {};

    auto op_kind = underlying.op_kind(0);

    // Memory operand: call [addr] or call [reg + offset]
    if (op_kind == iced_x86::OpKind::MEMORY) {
        auto base_reg = underlying.memory_base();
        auto displacement = underlying.memory_displacement64();

        // Check for import call: call [__imp_func]
        if (base_reg == iced_x86::Register::RIP || base_reg == iced_x86::Register::NONE) {
            Address target_addr = (base_reg == iced_x86::Register::RIP)
                ? call_instr.next_ip() + displacement
                : displacement;

            if (config_.resolve_imports && is_import_call(target_addr)) {
                return analyze_import_call(call_address, target_addr);
            }
        }

        // Check for vtable call: call [rcx + vtable_offset]
        if (config_.resolve_vtables && base_reg != iced_x86::Register::NONE) {
            auto info = analyze_vtable_call(instructions, call_index);
            if (info.type != IndirectCallType::Unknown) {
                return info;
            }
        }
    }

    // Register operand: call reg
    if (op_kind == iced_x86::OpKind::REGISTER) {
        auto reg = underlying.op_register(0);
        return analyze_register_call(instructions, call_index, reg);
    }

    IndirectCallInfo info;
    info.call_address = call_address;
    info.type = IndirectCallType::Unknown;
    return info;
}

std::vector<IndirectCallInfo> IndirectCallResolver::analyze_function(const CFG& cfg) {
    std::vector<IndirectCallInfo> results;

    cfg.for_each_block([&](const BasicBlock& block) {
        for (const auto& instr : block.instructions()) {
            if (instr.is_call() && instr.flow_type() == FlowType::IndirectCall) {
                auto info = analyze_call(block, instr.ip());
                if (info.call_address != INVALID_ADDRESS) {
                    results.push_back(std::move(info));
                }
            }
        }
    });

    return results;
}

const VTableInfo* IndirectCallResolver::find_vtable(Address addr) const {
    auto it = vtable_map_.find(addr);
    if (it != vtable_map_.end()) {
        return &vtables_[it->second];
    }
    return nullptr;
}

bool IndirectCallResolver::is_import_call(Address call_target) const {
    // Check if target is in IAT
    if (!iat_built_) {
        const_cast<IndirectCallResolver*>(this)->build_iat_map();
    }
    return iat_map_.count(call_target) > 0;
}

std::optional<std::pair<std::string, std::string>>
IndirectCallResolver::resolve_import(Address iat_entry) const {
    if (!iat_built_) {
        const_cast<IndirectCallResolver*>(this)->build_iat_map();
    }

    auto it = iat_map_.find(iat_entry);
    if (it != iat_map_.end()) {
        return it->second;
    }
    return std::nullopt;
}

IndirectCallInfo IndirectCallResolver::analyze_vtable_call(
    const std::vector<Instruction>& instructions,
    std::size_t call_index
) {
    const auto& call_instr = instructions[call_index];
    const auto& underlying = call_instr.raw();

    IndirectCallInfo info;
    info.call_address = call_instr.ip();

    // Pattern: call [reg + offset]
    auto base_reg = underlying.memory_base();
    auto offset = static_cast<std::int32_t>(underlying.memory_displacement32());

    // Look for where base_reg was loaded (typically from 'this' pointer)
    // Common pattern: mov reg, [rcx] or mov reg, [this_ptr + vtable_ptr_offset]

    for (std::size_t i = call_index; i > 0 && i > call_index - config_.backtrack_limit; --i) {
        const auto& instr = instructions[i - 1];
        const auto& u = instr.raw();

        if (u.mnemonic() == iced_x86::Mnemonic::MOV &&
            u.op_count() >= 2 &&
            u.op_kind(0) == iced_x86::OpKind::REGISTER &&
            u.op_register(0) == base_reg &&
            u.op_kind(1) == iced_x86::OpKind::MEMORY) {

            // Found where vtable pointer was loaded
            auto src_base = u.memory_base();
            auto src_offset = u.memory_displacement64();

            // If loaded from [rcx] or [rdx] etc, this is likely a vtable call
            // rcx is 'this' in Microsoft x64 calling convention

            if (src_base == iced_x86::Register::RCX ||
                src_base == iced_x86::Register::RDX ||
                src_base == iced_x86::Register::R8 ||
                src_base == iced_x86::Register::R9) {

                info.type = IndirectCallType::VTableCall;
                info.vtable_offset = offset;
                info.confidence = 70;

                // vtable index = offset / pointer_size
                std::size_t vtable_index = offset / 8;  // 64-bit

                // Try to resolve targets if we have vtable information
                // (would require class hierarchy analysis)

                return info;
            }
        }
    }

    // Could still be vtable call even if we didn't find the load
    if (offset >= 0 && (offset % 8) == 0) {
        info.type = IndirectCallType::VTableCall;
        info.vtable_offset = offset;
        info.confidence = 40;
    }

    return info;
}

IndirectCallInfo IndirectCallResolver::analyze_import_call(
    Address call_address,
    Address target_address
) {
    IndirectCallInfo info;
    info.call_address = call_address;
    info.type = IndirectCallType::ImportCall;

    auto import_info = resolve_import(target_address);
    if (import_info) {
        info.import_name = import_info->first;
        info.import_module = import_info->second;
        info.confidence = 100;

        // The actual target is what's stored at the IAT entry
        auto data = binary_->memory().read(target_address, 8);
        if (data && data->size() >= 8) {
            Address actual_target;
            std::memcpy(&actual_target, data->data(), 8);
            if (actual_target != 0) {
                info.targets.push_back(actual_target);
            }
        }
    }

    return info;
}

IndirectCallInfo IndirectCallResolver::analyze_register_call(
    const std::vector<Instruction>& instructions,
    std::size_t call_index,
    iced_x86::Register reg
) {
    IndirectCallInfo info;
    info.call_address = instructions[call_index].ip();
    info.type = IndirectCallType::RegisterCall;

    if (!config_.track_register_flow) {
        return info;
    }

    // Track where the register value came from
    for (std::size_t i = call_index; i > 0 && i > call_index - config_.backtrack_limit; --i) {
        const auto& instr = instructions[i - 1];
        const auto& u = instr.raw();

        // Check if this instruction defines our register
        if (u.op_count() >= 1 &&
            u.op_kind(0) == iced_x86::OpKind::REGISTER &&
            u.op_register(0) == reg) {

            switch (u.mnemonic()) {
                case iced_x86::Mnemonic::MOV:
                    if (u.op_count() >= 2) {
                        auto src_kind = u.op_kind(1);

                        // mov reg, [mem] - could be loading function pointer
                        if (src_kind == iced_x86::OpKind::MEMORY) {
                            auto mem_base = u.memory_base();
                            auto mem_disp = u.memory_displacement64();

                            // Check if loading from IAT
                            Address load_addr = INVALID_ADDRESS;
                            if (mem_base == iced_x86::Register::RIP) {
                                load_addr = instr.next_ip() + mem_disp;
                            } else if (mem_base == iced_x86::Register::NONE) {
                                load_addr = mem_disp;
                            }

                            if (load_addr != INVALID_ADDRESS && is_import_call(load_addr)) {
                                auto import_info = resolve_import(load_addr);
                                if (import_info) {
                                    info.type = IndirectCallType::ImportCall;
                                    info.import_name = import_info->first;
                                    info.import_module = import_info->second;
                                    info.confidence = 90;
                                }
                            } else if (load_addr != INVALID_ADDRESS) {
                                info.type = IndirectCallType::FunctionPointer;
                                info.confidence = 60;
                            }
                        }
                        // mov reg, imm - direct function address
                        else if (src_kind == iced_x86::OpKind::IMMEDIATE64) {
                            Address target = u.immediate64();
                            if (binary_->memory().is_executable(target)) {
                                info.targets.push_back(target);
                                info.confidence = 95;
                            }
                        }
                    }
                    return info;

                case iced_x86::Mnemonic::LEA:
                    // lea reg, [target] - getting address of function
                    if (u.op_count() >= 2 && u.op_kind(1) == iced_x86::OpKind::MEMORY) {
                        auto mem_base = u.memory_base();
                        auto mem_disp = u.memory_displacement64();

                        if (mem_base == iced_x86::Register::RIP) {
                            Address target = instr.next_ip() + mem_disp;
                            if (binary_->memory().is_executable(target)) {
                                info.targets.push_back(target);
                                info.confidence = 90;
                            }
                        }
                    }
                    return info;

                default:
                    // Some other operation defines the register
                    info.type = IndirectCallType::ComputedCall;
                    info.confidence = 20;
                    return info;
            }
        }
    }

    return info;
}

std::optional<VTableInfo> IndirectCallResolver::discover_vtable(Address addr) {
    VTableAnalyzer analyzer(binary_);

    if (!analyzer.is_possible_vtable(addr)) {
        return std::nullopt;
    }

    auto entries = analyzer.read_vtable(addr, config_.max_vtable_size);
    if (entries.empty()) {
        return std::nullopt;
    }

    VTableInfo info;
    info.address = addr;
    info.entries = std::move(entries);
    info.class_name = analyzer.find_class_name(addr).value_or("");

    return info;
}

void IndirectCallResolver::build_iat_map() {
    if (iat_built_) return;

    const auto* imports = binary_->imports();
    if (!imports) {
        iat_built_ = true;
        return;
    }

    Address base = binary_->image_base();

    for (const auto& module : imports->modules) {
        for (const auto& func : module.functions) {
            Address iat_addr = base + func.iat_rva;
            iat_map_[iat_addr] = {func.name, module.name};
        }
    }

    iat_built_ = true;
}

// VTableAnalyzer implementation
VTableAnalyzer::VTableAnalyzer(std::shared_ptr<loader::Binary> binary)
    : binary_(std::move(binary))
{}

std::vector<VTableInfo> VTableAnalyzer::find_vtables() {
    std::vector<VTableInfo> results;

    // Strategy: scan read-only data sections for arrays of function pointers
    const auto& sections = binary_->sections();

    for (const auto& section : sections) {
        // Skip writable or executable sections (want read-only data)
        if (section.is_writable()) continue;
        if (section.is_executable()) continue;

        Address section_start = section.virtual_address;
        Address section_end = section_start + section.virtual_size;

        // Scan for potential vtables
        for (Address addr = section_start; addr < section_end - 8; addr += 8) {
            if (is_possible_vtable(addr)) {
                auto entries = read_vtable(addr);
                if (entries.size() >= 2) {  // At least 2 entries for a vtable
                    VTableInfo info;
                    info.address = addr;
                    info.entries = std::move(entries);

                    // Try to find class name from RTTI
                    check_msvc_rtti(addr, info);

                    results.push_back(std::move(info));

                    // Skip past this vtable
                    addr += info.entries.size() * 8;
                }
            }
        }
    }

    return results;
}

bool VTableAnalyzer::is_possible_vtable(Address addr) const {
    // Read first entry
    auto data = binary_->memory().read(addr, 8);
    if (!data || data->size() < 8) return false;

    Address first_entry;
    std::memcpy(&first_entry, data->data(), 8);

    // First entry should be executable
    return binary_->memory().is_executable(first_entry);
}

std::vector<Address> VTableAnalyzer::read_vtable(Address addr, std::size_t max_entries) {
    std::vector<Address> entries;
    entries.reserve(max_entries);

    auto data = binary_->memory().read(addr, max_entries * 8);
    if (!data) return entries;

    const std::uint8_t* ptr = data->data();
    std::size_t available = data->size() / 8;

    for (std::size_t i = 0; i < std::min(max_entries, available); ++i) {
        Address entry;
        std::memcpy(&entry, ptr + i * 8, 8);

        // Stop if entry is not a valid code address
        if (entry == 0 || !binary_->memory().is_executable(entry)) {
            break;
        }

        entries.push_back(entry);
    }

    return entries;
}

std::optional<std::string> VTableAnalyzer::find_class_name(Address vtable_addr) const {
    // MSVC RTTI: vtable[-1] points to Complete Object Locator
    // COL contains pointer to TypeDescriptor which has the mangled name

    auto data = binary_->memory().read(vtable_addr - 8, 8);
    if (!data || data->size() < 8) return std::nullopt;

    Address col_ptr;
    std::memcpy(&col_ptr, data->data(), 8);

    if (col_ptr == 0) return std::nullopt;

    // Read COL to get TypeDescriptor offset
    // This is simplified - full implementation would parse the structures

    return std::nullopt;  // TODO: Implement full RTTI parsing
}

bool VTableAnalyzer::check_msvc_rtti(Address vtable_addr, VTableInfo& info) const {
    // MSVC RTTI structure:
    // vtable[-1] = pointer to _RTTICompleteObjectLocator
    // _RTTICompleteObjectLocator contains offset to _RTTITypeDescriptor

    auto data = binary_->memory().read(vtable_addr - 8, 8);
    if (!data || data->size() < 8) return false;

    Address col_ptr;
    std::memcpy(&col_ptr, data->data(), 8);

    if (col_ptr == 0 || !binary_->memory().is_valid_address(col_ptr)) {
        return false;
    }

    info.type_info = col_ptr;

    // Try to read class name - this would require full RTTI parsing
    // For now, just mark that we found RTTI

    return true;
}

} // namespace picanha::analysis
