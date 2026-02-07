#pragma once

#include <picanha/core/types.hpp>
#include <picanha/analysis/xref.hpp>
#include <imgui.h>
#include <string>
#include <vector>
#include <functional>

namespace picanha::ui {

class Application;

// XRef list entry for display
struct XRefEntry {
    Address from{INVALID_ADDRESS};
    Address to{INVALID_ADDRESS};
    analysis::XRefType type{analysis::XRefType::Unknown};
    std::string from_name;  // Function/symbol name at 'from'
    std::string to_name;    // Function/symbol name at 'to'
    bool is_selected{false};
};

// XRef display mode
enum class XRefMode {
    ToAddress,    // Show xrefs TO the target address
    FromAddress,  // Show xrefs FROM the target address
    Both,         // Show both directions
};

// XRef filter options
struct XRefFilter {
    bool show_calls{true};
    bool show_jumps{true};
    bool show_reads{true};
    bool show_writes{true};
    bool show_data{true};
};

// XRef list panel
class XRefList {
public:
    explicit XRefList(Application* app);
    ~XRefList();

    // Rendering
    void render();

    // Set target address to show xrefs for
    void set_target(Address address, XRefMode mode = XRefMode::ToAddress);
    [[nodiscard]] Address target() const { return target_; }
    [[nodiscard]] XRefMode mode() const { return mode_; }

    // Selection
    void select_xref(std::size_t index);
    [[nodiscard]] std::size_t selected_index() const { return selected_index_; }

    // Filter
    [[nodiscard]] XRefFilter& filter() { return filter_; }
    [[nodiscard]] const XRefFilter& filter() const { return filter_; }
    void apply_filter();

    // Callbacks
    using NavigateCallback = std::function<void(Address)>;
    void set_navigate_callback(NavigateCallback callback) { on_navigate_ = std::move(callback); }

    // Refresh
    void refresh();

private:
    // Rendering helpers
    void render_header();
    void render_table();
    void render_context_menu();

    // Filtering
    [[nodiscard]] bool passes_filter(const analysis::XRef& xref) const;

    // Entry management
    void rebuild_entries();
    XRefEntry make_entry(const analysis::XRef& xref) const;

    // Type to string
    [[nodiscard]] static const char* type_name(analysis::XRefType type);
    [[nodiscard]] static ImU32 type_color(analysis::XRefType type);

    Application* app_;

    // Target
    Address target_{INVALID_ADDRESS};
    XRefMode mode_{XRefMode::ToAddress};

    // Entries
    std::vector<XRefEntry> entries_;
    std::vector<std::size_t> filtered_indices_;

    // Selection
    std::size_t selected_index_{0};

    // Filter
    XRefFilter filter_;

    // Callback
    NavigateCallback on_navigate_;

    // State
    bool need_refresh_{true};
};

} // namespace picanha::ui
