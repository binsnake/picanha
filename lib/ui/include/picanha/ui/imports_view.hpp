#pragma once

#include <picanha/core/types.hpp>
#include <picanha/analysis/symbol.hpp>
#include <imgui.h>
#include <string>
#include <vector>
#include <map>
#include <functional>

namespace picanha::ui {

class Application;

// Import entry for display
struct ImportEntry {
    Address address{INVALID_ADDRESS};
    std::string name;
    std::uint16_t ordinal{0};
    bool by_ordinal{false};
};

// Module (DLL) with its imports
struct ImportModule {
    std::string name;
    std::vector<ImportEntry> imports;
    bool expanded{true};  // Tree node state
};

// Imports view with IDA-style tree structure
class ImportsView {
public:
    explicit ImportsView(Application* app);
    ~ImportsView();

    // Rendering
    void render();

    // Selection
    void select_address(Address address);
    [[nodiscard]] Address selected_address() const { return selected_address_; }

    // Callbacks
    using SelectionCallback = std::function<void(Address)>;
    void set_selection_callback(SelectionCallback callback) { on_select_ = std::move(callback); }

    // Refresh
    void refresh();

private:
    // Rendering helpers
    void render_toolbar();
    void render_tree();

    // Entry management
    void rebuild_modules();

    Application* app_;

    // Modules grouped by DLL
    std::vector<ImportModule> modules_;

    // Selection
    Address selected_address_{INVALID_ADDRESS};

    // Filter
    char filter_text_[256]{};
    std::string filter_string_;

    // Callback
    SelectionCallback on_select_;

    // State
    bool need_refresh_{true};
};

} // namespace picanha::ui
