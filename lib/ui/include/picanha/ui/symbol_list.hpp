#pragma once

#include <picanha/core/types.hpp>
#include <picanha/analysis/symbol.hpp>
#include <imgui.h>
#include <string>
#include <vector>
#include <functional>

namespace picanha::ui {

class Application;

// Symbol list entry for display
struct SymbolEntry {
    Address address{INVALID_ADDRESS};
    std::string name;
    analysis::SymbolType type{analysis::SymbolType::Unknown};
    analysis::SymbolFlags flags{};
    std::string module;  // For imports
    bool is_selected{false};
};

// Symbol filter options
struct SymbolFilter {
    std::string name_filter;
    bool show_functions{true};
    bool show_data{true};
    bool show_imports{true};
    bool show_exports{true};
    bool show_labels{true};
    bool show_strings{true};
    Address address_min{0};
    Address address_max{INVALID_ADDRESS};
};

// Sort options
enum class SymbolSortColumn {
    Address,
    Name,
    Type,
    Module,
};

// Symbol list panel
class SymbolList {
public:
    explicit SymbolList(Application* app);
    ~SymbolList();

    // Rendering
    void render();

    // Selection
    void select_symbol(Address address);
    [[nodiscard]] Address selected_address() const { return selected_address_; }

    // Filter
    [[nodiscard]] SymbolFilter& filter() { return filter_; }
    [[nodiscard]] const SymbolFilter& filter() const { return filter_; }
    void apply_filter();

    // Callbacks
    using SelectionCallback = std::function<void(Address)>;
    void set_selection_callback(SelectionCallback callback) { on_select_ = std::move(callback); }

    // Refresh
    void refresh();

private:
    // Rendering helpers
    void render_toolbar();
    void render_filter_popup();
    void render_table();
    void render_context_menu();

    // Sorting
    void sort_entries();

    // Filtering
    [[nodiscard]] bool passes_filter(const analysis::Symbol& sym) const;

    // Entry management
    void rebuild_entries();
    SymbolEntry make_entry(const analysis::Symbol& sym) const;

    // Type to string
    [[nodiscard]] static const char* type_name(analysis::SymbolType type);

    Application* app_;

    // Entries
    std::vector<SymbolEntry> entries_;
    std::vector<std::size_t> filtered_indices_;

    // Selection
    Address selected_address_{INVALID_ADDRESS};
    std::size_t selected_index_{0};

    // Filter
    SymbolFilter filter_;
    char filter_text_[256]{};
    bool filter_popup_open_{false};

    // Sorting
    SymbolSortColumn sort_column_{SymbolSortColumn::Address};
    bool sort_ascending_{true};

    // Callback
    SelectionCallback on_select_;

    // State
    bool need_refresh_{true};
    bool scroll_to_selected_{false};
};

} // namespace picanha::ui
