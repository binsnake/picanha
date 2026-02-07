#include <picanha/ui/symbol_list.hpp>
#include <picanha/ui/app.hpp>
#include <imgui.h>

#include <algorithm>
#include <format>

namespace picanha::ui {

SymbolList::SymbolList(Application* app)
    : app_(app)
{
}

SymbolList::~SymbolList() = default;

void SymbolList::render() {
    if (need_refresh_) {
        rebuild_entries();
        need_refresh_ = false;
    }

    render_toolbar();
    ImGui::Separator();
    render_table();
    // Context menu is handled per-item in render_table()
}

void SymbolList::select_symbol(Address address) {
    selected_address_ = address;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].address == address) {
            selected_index_ = i;
            scroll_to_selected_ = true;
            break;
        }
    }
}

void SymbolList::apply_filter() {
    filtered_indices_.clear();

    for (std::size_t i = 0; i < entries_.size(); ++i) {
        const auto& entry = entries_[i];

        // Name filter
        if (!filter_.name_filter.empty()) {
            if (entry.name.find(filter_.name_filter) == std::string::npos) {
                continue;
            }
        }

        // Address range filter
        if (entry.address < filter_.address_min || entry.address > filter_.address_max) {
            continue;
        }

        // Type filters
        using Type = analysis::SymbolType;
        bool is_import = entry.type == Type::Import;
        bool is_export = entry.type == Type::Export;

        switch (entry.type) {
            case analysis::SymbolType::Function:
                if (!filter_.show_functions) continue;
                break;
            case analysis::SymbolType::Data:
                if (!filter_.show_data) continue;
                break;
            case analysis::SymbolType::Label:
                if (!filter_.show_labels) continue;
                break;
            case analysis::SymbolType::String:
                if (!filter_.show_strings) continue;
                break;
            default:
                break;
        }

        if (is_import && !filter_.show_imports) continue;
        if (is_export && !filter_.show_exports) continue;

        filtered_indices_.push_back(i);
    }

    sort_entries();
}

void SymbolList::refresh() {
    need_refresh_ = true;
}

void SymbolList::render_toolbar() {
    // Search box
    ImGui::SetNextItemWidth(200);
    if (ImGui::InputTextWithHint("##filter", "Filter symbols...", filter_text_, sizeof(filter_text_))) {
        filter_.name_filter = filter_text_;
        apply_filter();
    }

    ImGui::SameLine();
    if (ImGui::Button("Filter...")) {
        filter_popup_open_ = true;
    }

    ImGui::SameLine();
    ImGui::Text("%zu / %zu symbols", filtered_indices_.size(), entries_.size());

    // Filter popup
    if (filter_popup_open_) {
        render_filter_popup();
    }
}

void SymbolList::render_filter_popup() {
    ImGui::OpenPopup("Symbol Filter");

    if (ImGui::BeginPopupModal("Symbol Filter", &filter_popup_open_, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Show types:");
        ImGui::Checkbox("Functions", &filter_.show_functions);
        ImGui::Checkbox("Data", &filter_.show_data);
        ImGui::Checkbox("Labels", &filter_.show_labels);
        ImGui::Checkbox("Strings", &filter_.show_strings);

        ImGui::Separator();
        ImGui::Text("Show flags:");
        ImGui::Checkbox("Imports", &filter_.show_imports);
        ImGui::Checkbox("Exports", &filter_.show_exports);

        ImGui::Separator();
        if (ImGui::Button("Apply", ImVec2(120, 0))) {
            apply_filter();
            filter_popup_open_ = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Reset", ImVec2(120, 0))) {
            filter_ = SymbolFilter{};
            std::memset(filter_text_, 0, sizeof(filter_text_));
            apply_filter();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            filter_popup_open_ = false;
        }

        ImGui::EndPopup();
    }
}

void SymbolList::render_table() {
    // Simple list - just symbol names, with tooltip for details
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(filtered_indices_.size()));

    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            std::size_t entry_idx = filtered_indices_[row];
            const auto& entry = entries_[entry_idx];

            bool is_selected = (entry.address == selected_address_);

            if (ImGui::Selectable(entry.name.c_str(), is_selected)) {
                selected_address_ = entry.address;
                selected_index_ = entry_idx;
                if (on_select_) {
                    on_select_(entry.address);
                }
            }

            // Tooltip with details
            if (ImGui::IsItemHovered()) {
                ImGui::BeginTooltip();
                ImGui::Text("Address: 0x%llX", static_cast<unsigned long long>(entry.address));
                ImGui::Text("Type: %s", type_name(entry.type));
                if (!entry.module.empty()) {
                    ImGui::Text("Module: %s", entry.module.c_str());
                }
                ImGui::EndTooltip();
            }

            // Double-click to navigate
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                app_->navigate_to(entry.address);
            }

            // Context menu
            if (ImGui::BeginPopupContextItem()) {
                ImGui::Text("Symbol: %s", entry.name.c_str());
                ImGui::Separator();

                if (ImGui::MenuItem("Go to")) {
                    app_->navigate_to(entry.address);
                }

                if (ImGui::MenuItem("Copy Address")) {
                    auto addr_str = std::format("0x{:016X}", entry.address);
                    ImGui::SetClipboardText(addr_str.c_str());
                }

                if (ImGui::MenuItem("Copy Name")) {
                    ImGui::SetClipboardText(entry.name.c_str());
                }

                ImGui::EndPopup();
            }
        }
    }

    // Scroll to selected if needed
    if (scroll_to_selected_) {
        for (std::size_t i = 0; i < filtered_indices_.size(); ++i) {
            if (entries_[filtered_indices_[i]].address == selected_address_) {
                float item_pos_y = clipper.ItemsHeight * i;
                ImGui::SetScrollY(item_pos_y);
                break;
            }
        }
        scroll_to_selected_ = false;
    }
}

void SymbolList::render_context_menu() {
    if (ImGui::BeginPopupContextItem("SymbolContextMenu")) {
        if (selected_address_ != INVALID_ADDRESS) {
            const auto& entry = entries_[selected_index_];

            ImGui::Text("Symbol: %s", entry.name.c_str());
            ImGui::Separator();

            if (ImGui::MenuItem("Go to")) {
                app_->navigate_to(entry.address);
            }

            if (ImGui::MenuItem("Copy Address")) {
                auto addr_str = std::format("0x{:016X}", entry.address);
                ImGui::SetClipboardText(addr_str.c_str());
            }

            if (ImGui::MenuItem("Copy Name")) {
                ImGui::SetClipboardText(entry.name.c_str());
            }

            ImGui::Separator();

            if (ImGui::MenuItem("Rename...")) {
                // TODO: Open rename dialog
            }

            if (ImGui::MenuItem("Show XRefs")) {
                // TODO: Show xrefs to this symbol
            }
        }
        ImGui::EndPopup();
    }
}

void SymbolList::sort_entries() {
    std::sort(filtered_indices_.begin(), filtered_indices_.end(),
        [this](std::size_t a, std::size_t b) {
            const auto& ea = entries_[a];
            const auto& eb = entries_[b];

            int cmp = 0;
            switch (sort_column_) {
                case SymbolSortColumn::Address:
                    cmp = (ea.address < eb.address) ? -1 : (ea.address > eb.address) ? 1 : 0;
                    break;
                case SymbolSortColumn::Name:
                    cmp = ea.name.compare(eb.name);
                    break;
                case SymbolSortColumn::Type:
                    cmp = static_cast<int>(ea.type) - static_cast<int>(eb.type);
                    break;
                case SymbolSortColumn::Module:
                    cmp = ea.module.compare(eb.module);
                    break;
            }

            return sort_ascending_ ? (cmp < 0) : (cmp > 0);
        });
}

bool SymbolList::passes_filter(const analysis::Symbol& sym) const {
    // Basic name filter
    if (!filter_.name_filter.empty()) {
        if (sym.name.find(filter_.name_filter) == std::string::npos) {
            return false;
        }
    }

    // Address filter
    if (sym.address < filter_.address_min || sym.address > filter_.address_max) {
        return false;
    }

    return true;
}

void SymbolList::rebuild_entries() {
    entries_.clear();

    app_->symbols().for_each([this](const analysis::Symbol& sym) {
        entries_.push_back(make_entry(sym));
    });

    // Reset filter indices
    filtered_indices_.clear();
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        filtered_indices_.push_back(i);
    }

    apply_filter();
}

SymbolEntry SymbolList::make_entry(const analysis::Symbol& sym) const {
    SymbolEntry entry;
    entry.address = sym.address;
    entry.name = sym.name;
    entry.type = sym.type;
    entry.flags = sym.flags;
    entry.module = sym.module_name;
    return entry;
}

const char* SymbolList::type_name(analysis::SymbolType type) {
    switch (type) {
        case analysis::SymbolType::Function: return "Function";
        case analysis::SymbolType::Data: return "Data";
        case analysis::SymbolType::Label: return "Label";
        case analysis::SymbolType::String: return "String";
        case analysis::SymbolType::Section: return "Section";
        case analysis::SymbolType::Import: return "Import";
        case analysis::SymbolType::Export: return "Export";
        default: return "Unknown";
    }
}

} // namespace picanha::ui
