#pragma once

#include "picanha/analysis/symbol.hpp"
#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>
#include <memory>
#include <vector>
#include <map>
#include <unordered_map>
#include <string>
#include <functional>
#include <optional>

namespace picanha::analysis {

// Configuration for symbol table building
struct SymbolTableConfig {
    bool import_exports{true};
    bool import_imports{true};
    bool auto_generate_names{true};
    bool detect_strings{true};
    std::string function_prefix{"sub_"};
    std::string data_prefix{"dat_"};
    std::string label_prefix{"loc_"};
    std::string string_prefix{"str_"};
};

// Symbol table - manages all symbols in the binary
class SymbolTable {
public:
    SymbolTable();
    explicit SymbolTable(const SymbolTableConfig& config);

    // Build from binary
    void build_from_binary(std::shared_ptr<loader::Binary> binary);

    // Symbol creation
    SymbolId add(Symbol symbol);
    SymbolId add_function(Address addr, const std::string& name = "");
    SymbolId add_data(Address addr, Size size, const std::string& name = "");
    SymbolId add_label(Address addr, const std::string& name = "");
    SymbolId add_string(Address addr, Size size, const std::string& value = "");
    SymbolId add_import(Address addr, const std::string& name, const std::string& module);
    SymbolId add_export(Address addr, const std::string& name, std::uint16_t ordinal = 0);

    // Symbol modification
    void set_name(SymbolId id, const std::string& name);
    void set_demangled_name(SymbolId id, const std::string& name);
    void set_type(SymbolId id, SymbolType type);
    void set_size(SymbolId id, Size size);
    void set_flags(SymbolId id, SymbolFlags flags);
    void add_flag(SymbolId id, SymbolFlags flag);
    void remove_flag(SymbolId id, SymbolFlags flag);

    // Symbol removal
    void remove(SymbolId id);
    void remove_at(Address addr);
    void clear();

    // Symbol lookup by ID
    [[nodiscard]] Symbol* get(SymbolId id);
    [[nodiscard]] const Symbol* get(SymbolId id) const;

    // Symbol lookup by address
    [[nodiscard]] Symbol* find_at(Address addr);
    [[nodiscard]] const Symbol* find_at(Address addr) const;

    // Find symbol containing address
    [[nodiscard]] Symbol* find_containing(Address addr);
    [[nodiscard]] const Symbol* find_containing(Address addr) const;

    // Symbol lookup by name
    [[nodiscard]] Symbol* find_by_name(const std::string& name);
    [[nodiscard]] const Symbol* find_by_name(const std::string& name) const;

    // Find symbols in range
    [[nodiscard]] std::vector<Symbol*> find_in_range(Address start, Address end);
    [[nodiscard]] std::vector<const Symbol*> find_in_range(Address start, Address end) const;

    // Find symbols by type
    [[nodiscard]] std::vector<Symbol*> find_by_type(SymbolType type);
    [[nodiscard]] std::vector<const Symbol*> find_by_type(SymbolType type) const;

    // Find functions
    [[nodiscard]] std::vector<Symbol*> get_functions();
    [[nodiscard]] std::vector<const Symbol*> get_functions() const;

    // Find imports
    [[nodiscard]] std::vector<Symbol*> get_imports();
    [[nodiscard]] std::vector<const Symbol*> get_imports() const;

    // Find exports
    [[nodiscard]] std::vector<Symbol*> get_exports();
    [[nodiscard]] std::vector<const Symbol*> get_exports() const;

    // Check existence
    [[nodiscard]] bool has_symbol_at(Address addr) const;
    [[nodiscard]] bool has_symbol_named(const std::string& name) const;

    // Get name for address (creates auto-name if needed)
    [[nodiscard]] std::string get_name_at(Address addr);
    [[nodiscard]] std::string get_name_at(Address addr) const;

    // Generate unique name
    [[nodiscard]] std::string generate_function_name(Address addr) const;
    [[nodiscard]] std::string generate_data_name(Address addr) const;
    [[nodiscard]] std::string generate_label_name(Address addr) const;

    // Statistics
    [[nodiscard]] std::size_t count() const;
    [[nodiscard]] std::size_t count_functions() const;
    [[nodiscard]] std::size_t count_imports() const;
    [[nodiscard]] std::size_t count_exports() const;

    // Iteration
    using SymbolVisitor = std::function<void(Symbol&)>;
    using ConstSymbolVisitor = std::function<void(const Symbol&)>;

    void for_each(SymbolVisitor visitor);
    void for_each(ConstSymbolVisitor visitor) const;
    void for_each_function(SymbolVisitor visitor);
    void for_each_function(ConstSymbolVisitor visitor) const;

    // Get all symbols (sorted by address)
    [[nodiscard]] std::vector<Symbol*> get_all();
    [[nodiscard]] std::vector<const Symbol*> get_all() const;

    // Serialization support
    [[nodiscard]] const std::vector<Symbol>& symbols() const { return symbols_; }
    [[nodiscard]] std::vector<Symbol>& mutable_symbols() { return symbols_; }

private:
    // Add symbol from binary export
    void add_from_export(const loader::pe::Export& exp);

    // Add symbol from binary import
    void add_from_import(const loader::pe::ImportedFunction& func,
                          const std::string& module_name, Address base);

    // Rebuild indices
    void rebuild_indices();

    SymbolTableConfig config_;
    std::vector<Symbol> symbols_;
    SymbolId next_id_{0};

    // Indices
    std::map<Address, SymbolId> address_index_;             // Exact address match
    std::unordered_map<std::string, SymbolId> name_index_;  // Name lookup
};

} // namespace picanha::analysis
