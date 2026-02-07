#pragma once

#include <picanha/core/types.hpp>
#include <picanha/analysis/function.hpp>
#include <imgui.h>
#include <string>
#include <vector>
#include <functional>

namespace picanha::ui {

class Application;

// Function list entry for display
struct FunctionEntry {
    FunctionId id{INVALID_FUNCTION_ID};
    Address address{INVALID_ADDRESS};
    std::string name;
    std::string segment;  // Section name (e.g., ".text")
    Size size{0};
    std::size_t block_count{0};
    std::size_t xref_count{0};
    analysis::FunctionType type{analysis::FunctionType::Normal};
    analysis::FunctionFlags flags{};
    bool is_selected{false};
};

// Function list filter options
struct FunctionFilter {
    std::string name_filter;
    bool show_imports{true};
    bool show_exports{true};
    bool show_thunks{true};
    bool show_library{true};
    bool show_user{true};
    bool show_noreturn{true};
    Address address_min{0};
    Address address_max{INVALID_ADDRESS};
    Size size_min{0};
    Size size_max{INVALID_ADDRESS};
};

// Sort options
enum class FunctionSortColumn {
    Address,
    Name,
    Size,
    BlockCount,
    XRefCount,
};

// Function list panel
class FunctionList {
public:
    explicit FunctionList(Application* app);
    ~FunctionList();

    // Rendering
    void render();

    // Selection
    void select_function(FunctionId id);
    void select_address(Address address);
    [[nodiscard]] FunctionId selected_function() const { return selected_id_; }

    // Filter
    [[nodiscard]] FunctionFilter& filter() { return filter_; }
    [[nodiscard]] const FunctionFilter& filter() const { return filter_; }
    void apply_filter();

    // Callbacks
    using SelectionCallback = std::function<void(FunctionId)>;
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
    [[nodiscard]] bool passes_filter(const analysis::Function& func) const;

    // Entry management
    void rebuild_entries();
    FunctionEntry make_entry(const analysis::Function& func) const;

    Application* app_;

    // Entries
    std::vector<FunctionEntry> entries_;
    std::vector<std::size_t> filtered_indices_;

    // Selection
    FunctionId selected_id_{INVALID_FUNCTION_ID};
    std::size_t selected_index_{0};

    // Filter
    FunctionFilter filter_;
    char filter_text_[256]{};
    bool filter_popup_open_{false};

    // Sorting
    FunctionSortColumn sort_column_{FunctionSortColumn::Address};
    bool sort_ascending_{true};

    // Callback
    SelectionCallback on_select_;

    // State
    bool need_refresh_{true};
    bool scroll_to_selected_{false};
};

} // namespace picanha::ui
