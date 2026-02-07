#include "picanha/analysis/symbol_table.hpp"
#include <algorithm>
#include <format>

namespace picanha::analysis {

SymbolTable::SymbolTable()
    : config_{}
{}

SymbolTable::SymbolTable(const SymbolTableConfig& config)
    : config_(config)
{}

void SymbolTable::build_from_binary(std::shared_ptr<loader::Binary> binary) {
    Address base = binary->image_base();

    // Import exports
    if (config_.import_exports) {
        const auto* exports = binary->exports();
        if (exports) {
            for (const auto& exp : exports->exports) {
                add_from_export(exp);
            }
        }
    }

    // Import imports
    if (config_.import_imports) {
        const auto* imports = binary->imports();
        if (imports) {
            for (const auto& module : imports->modules) {
                for (const auto& func : module.functions) {
                    add_from_import(func, module.name, base);
                }
            }
        }
    }

    rebuild_indices();
}

void SymbolTable::add_from_export(const loader::pe::Export& exp) {
    if (exp.is_forwarded) {
        // Forwarder exports don't have local addresses
        return;
    }

    Symbol sym;
    sym.id = next_id_++;
    sym.address = exp.address;  // Already a VA
    sym.name = exp.name;
    sym.type = SymbolType::Export;
    sym.visibility = SymbolVisibility::Global;
    sym.source = SymbolSource::Export;
    sym.ordinal = exp.ordinal;

    symbols_.push_back(std::move(sym));
}

void SymbolTable::add_from_import(const loader::pe::ImportedFunction& func,
                                   const std::string& module_name, Address base) {
    Symbol sym;
    sym.id = next_id_++;
    sym.address = base + func.iat_rva;  // IAT entry address
    sym.name = func.name;
    sym.module_name = module_name;
    sym.type = SymbolType::Import;
    sym.visibility = SymbolVisibility::Global;
    sym.source = SymbolSource::Import;
    sym.ordinal = func.ordinal;

    if (func.by_ordinal) {
        // Name is empty, use ordinal-based name
        sym.name = std::format("{}!Ordinal_{}", module_name, func.ordinal);
    }

    symbols_.push_back(std::move(sym));
}

SymbolId SymbolTable::add(Symbol symbol) {
    symbol.id = next_id_++;
    SymbolId id = symbol.id;

    address_index_[symbol.address] = id;
    if (!symbol.name.empty()) {
        name_index_[symbol.name] = id;
    }

    symbols_.push_back(std::move(symbol));
    return id;
}

SymbolId SymbolTable::add_function(Address addr, const std::string& name) {
    Symbol sym;
    sym.address = addr;
    sym.name = name.empty() ? generate_function_name(addr) : name;
    sym.type = SymbolType::Function;
    sym.source = name.empty() ? SymbolSource::Auto : SymbolSource::User;
    return add(std::move(sym));
}

SymbolId SymbolTable::add_data(Address addr, Size size, const std::string& name) {
    Symbol sym;
    sym.address = addr;
    sym.size = size;
    sym.name = name.empty() ? generate_data_name(addr) : name;
    sym.type = SymbolType::Data;
    sym.source = name.empty() ? SymbolSource::Auto : SymbolSource::User;
    return add(std::move(sym));
}

SymbolId SymbolTable::add_label(Address addr, const std::string& name) {
    Symbol sym;
    sym.address = addr;
    sym.name = name.empty() ? generate_label_name(addr) : name;
    sym.type = SymbolType::Label;
    sym.source = name.empty() ? SymbolSource::Auto : SymbolSource::User;
    return add(std::move(sym));
}

SymbolId SymbolTable::add_string(Address addr, Size size, const std::string& value) {
    Symbol sym;
    sym.address = addr;
    sym.size = size;
    sym.name = std::format("{}{:X}", config_.string_prefix, addr);
    sym.demangled_name = value;  // Store string value in demangled_name
    sym.type = SymbolType::String;
    sym.source = SymbolSource::Analysis;
    return add(std::move(sym));
}

SymbolId SymbolTable::add_import(Address addr, const std::string& name, const std::string& module) {
    Symbol sym;
    sym.address = addr;
    sym.name = name;
    sym.module_name = module;
    sym.type = SymbolType::Import;
    sym.visibility = SymbolVisibility::Global;
    sym.source = SymbolSource::Import;
    return add(std::move(sym));
}

SymbolId SymbolTable::add_export(Address addr, const std::string& name, std::uint16_t ordinal) {
    Symbol sym;
    sym.address = addr;
    sym.name = name;
    sym.ordinal = ordinal;
    sym.type = SymbolType::Export;
    sym.visibility = SymbolVisibility::Global;
    sym.source = SymbolSource::Export;
    return add(std::move(sym));
}

void SymbolTable::set_name(SymbolId id, const std::string& name) {
    if (auto* sym = get(id)) {
        // Remove old name from index
        if (!sym->name.empty()) {
            name_index_.erase(sym->name);
        }
        sym->name = name;
        if (!name.empty()) {
            name_index_[name] = id;
        }
    }
}

void SymbolTable::set_demangled_name(SymbolId id, const std::string& name) {
    if (auto* sym = get(id)) {
        sym->demangled_name = name;
        if (!name.empty()) {
            sym->flags = sym->flags | SymbolFlags::IsDemangled;
        }
    }
}

void SymbolTable::set_type(SymbolId id, SymbolType type) {
    if (auto* sym = get(id)) {
        sym->type = type;
    }
}

void SymbolTable::set_size(SymbolId id, Size size) {
    if (auto* sym = get(id)) {
        sym->size = size;
    }
}

void SymbolTable::set_flags(SymbolId id, SymbolFlags flags) {
    if (auto* sym = get(id)) {
        sym->flags = flags;
    }
}

void SymbolTable::add_flag(SymbolId id, SymbolFlags flag) {
    if (auto* sym = get(id)) {
        sym->flags = sym->flags | flag;
    }
}

void SymbolTable::remove_flag(SymbolId id, SymbolFlags flag) {
    if (auto* sym = get(id)) {
        sym->flags = sym->flags & ~flag;
    }
}

void SymbolTable::remove(SymbolId id) {
    auto it = std::find_if(symbols_.begin(), symbols_.end(),
        [id](const Symbol& s) { return s.id == id; });

    if (it != symbols_.end()) {
        address_index_.erase(it->address);
        if (!it->name.empty()) {
            name_index_.erase(it->name);
        }
        symbols_.erase(it);
    }
}

void SymbolTable::remove_at(Address addr) {
    auto it = address_index_.find(addr);
    if (it != address_index_.end()) {
        remove(it->second);
    }
}

void SymbolTable::clear() {
    symbols_.clear();
    address_index_.clear();
    name_index_.clear();
    next_id_ = 0;
}

Symbol* SymbolTable::get(SymbolId id) {
    auto it = std::find_if(symbols_.begin(), symbols_.end(),
        [id](const Symbol& s) { return s.id == id; });
    return it != symbols_.end() ? &(*it) : nullptr;
}

const Symbol* SymbolTable::get(SymbolId id) const {
    auto it = std::find_if(symbols_.begin(), symbols_.end(),
        [id](const Symbol& s) { return s.id == id; });
    return it != symbols_.end() ? &(*it) : nullptr;
}

Symbol* SymbolTable::find_at(Address addr) {
    auto it = address_index_.find(addr);
    if (it != address_index_.end()) {
        return get(it->second);
    }
    return nullptr;
}

const Symbol* SymbolTable::find_at(Address addr) const {
    auto it = address_index_.find(addr);
    if (it != address_index_.end()) {
        return get(it->second);
    }
    return nullptr;
}

Symbol* SymbolTable::find_containing(Address addr) {
    // Find symbol where addr falls within [address, address+size)
    for (auto& sym : symbols_) {
        if (addr >= sym.address && addr < sym.address + sym.size) {
            return &sym;
        }
    }
    // Fallback: find closest symbol before this address
    auto it = address_index_.upper_bound(addr);
    if (it != address_index_.begin()) {
        --it;
        return get(it->second);
    }
    return nullptr;
}

const Symbol* SymbolTable::find_containing(Address addr) const {
    return const_cast<SymbolTable*>(this)->find_containing(addr);
}

Symbol* SymbolTable::find_by_name(const std::string& name) {
    auto it = name_index_.find(name);
    if (it != name_index_.end()) {
        return get(it->second);
    }
    return nullptr;
}

const Symbol* SymbolTable::find_by_name(const std::string& name) const {
    auto it = name_index_.find(name);
    if (it != name_index_.end()) {
        return get(it->second);
    }
    return nullptr;
}

std::vector<Symbol*> SymbolTable::find_in_range(Address start, Address end) {
    std::vector<Symbol*> result;
    for (auto& sym : symbols_) {
        if (sym.address >= start && sym.address < end) {
            result.push_back(&sym);
        }
    }
    std::sort(result.begin(), result.end(),
        [](const Symbol* a, const Symbol* b) { return a->address < b->address; });
    return result;
}

std::vector<const Symbol*> SymbolTable::find_in_range(Address start, Address end) const {
    std::vector<const Symbol*> result;
    for (const auto& sym : symbols_) {
        if (sym.address >= start && sym.address < end) {
            result.push_back(&sym);
        }
    }
    std::sort(result.begin(), result.end(),
        [](const Symbol* a, const Symbol* b) { return a->address < b->address; });
    return result;
}

std::vector<Symbol*> SymbolTable::find_by_type(SymbolType type) {
    std::vector<Symbol*> result;
    for (auto& sym : symbols_) {
        if (sym.type == type) {
            result.push_back(&sym);
        }
    }
    return result;
}

std::vector<const Symbol*> SymbolTable::find_by_type(SymbolType type) const {
    std::vector<const Symbol*> result;
    for (const auto& sym : symbols_) {
        if (sym.type == type) {
            result.push_back(&sym);
        }
    }
    return result;
}

std::vector<Symbol*> SymbolTable::get_functions() {
    std::vector<Symbol*> result;
    for (auto& sym : symbols_) {
        if (sym.is_function()) {
            result.push_back(&sym);
        }
    }
    return result;
}

std::vector<const Symbol*> SymbolTable::get_functions() const {
    std::vector<const Symbol*> result;
    for (const auto& sym : symbols_) {
        if (sym.is_function()) {
            result.push_back(&sym);
        }
    }
    return result;
}

std::vector<Symbol*> SymbolTable::get_imports() {
    return find_by_type(SymbolType::Import);
}

std::vector<const Symbol*> SymbolTable::get_imports() const {
    return find_by_type(SymbolType::Import);
}

std::vector<Symbol*> SymbolTable::get_exports() {
    return find_by_type(SymbolType::Export);
}

std::vector<const Symbol*> SymbolTable::get_exports() const {
    return find_by_type(SymbolType::Export);
}

bool SymbolTable::has_symbol_at(Address addr) const {
    return address_index_.find(addr) != address_index_.end();
}

bool SymbolTable::has_symbol_named(const std::string& name) const {
    return name_index_.find(name) != name_index_.end();
}

std::string SymbolTable::get_name_at(Address addr) {
    if (auto* sym = find_at(addr)) {
        return sym->display_name();
    }
    if (config_.auto_generate_names) {
        // Don't create a symbol, just return a generated name
        return std::format("{}{:X}", config_.label_prefix, addr);
    }
    return "";
}

std::string SymbolTable::get_name_at(Address addr) const {
    if (const auto* sym = find_at(addr)) {
        return sym->display_name();
    }
    return std::format("{}{:X}", config_.label_prefix, addr);
}

std::string SymbolTable::generate_function_name(Address addr) const {
    return std::format("{}{:X}", config_.function_prefix, addr);
}

std::string SymbolTable::generate_data_name(Address addr) const {
    return std::format("{}{:X}", config_.data_prefix, addr);
}

std::string SymbolTable::generate_label_name(Address addr) const {
    return std::format("{}{:X}", config_.label_prefix, addr);
}

std::size_t SymbolTable::count() const {
    return symbols_.size();
}

std::size_t SymbolTable::count_functions() const {
    return std::count_if(symbols_.begin(), symbols_.end(),
        [](const Symbol& s) { return s.is_function(); });
}

std::size_t SymbolTable::count_imports() const {
    return std::count_if(symbols_.begin(), symbols_.end(),
        [](const Symbol& s) { return s.type == SymbolType::Import; });
}

std::size_t SymbolTable::count_exports() const {
    return std::count_if(symbols_.begin(), symbols_.end(),
        [](const Symbol& s) { return s.type == SymbolType::Export; });
}

void SymbolTable::for_each(SymbolVisitor visitor) {
    for (auto& sym : symbols_) {
        visitor(sym);
    }
}

void SymbolTable::for_each(ConstSymbolVisitor visitor) const {
    for (const auto& sym : symbols_) {
        visitor(sym);
    }
}

void SymbolTable::for_each_function(SymbolVisitor visitor) {
    for (auto& sym : symbols_) {
        if (sym.is_function()) {
            visitor(sym);
        }
    }
}

void SymbolTable::for_each_function(ConstSymbolVisitor visitor) const {
    for (const auto& sym : symbols_) {
        if (sym.is_function()) {
            visitor(sym);
        }
    }
}

std::vector<Symbol*> SymbolTable::get_all() {
    std::vector<Symbol*> result;
    result.reserve(symbols_.size());
    for (auto& sym : symbols_) {
        result.push_back(&sym);
    }
    std::sort(result.begin(), result.end(),
        [](const Symbol* a, const Symbol* b) { return a->address < b->address; });
    return result;
}

std::vector<const Symbol*> SymbolTable::get_all() const {
    std::vector<const Symbol*> result;
    result.reserve(symbols_.size());
    for (const auto& sym : symbols_) {
        result.push_back(&sym);
    }
    std::sort(result.begin(), result.end(),
        [](const Symbol* a, const Symbol* b) { return a->address < b->address; });
    return result;
}

void SymbolTable::rebuild_indices() {
    address_index_.clear();
    name_index_.clear();

    for (const auto& sym : symbols_) {
        address_index_[sym.address] = sym.id;
        if (!sym.name.empty()) {
            name_index_[sym.name] = sym.id;
        }
    }
}

} // namespace picanha::analysis
