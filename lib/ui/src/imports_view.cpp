#include <picanha/ui/imports_view.hpp>
#include <picanha/ui/app.hpp>
#include <imgui.h>

#include <algorithm>
#include <format>

namespace picanha::ui {

ImportsView::ImportsView(Application* app)
    : app_(app)
{
}

ImportsView::~ImportsView() = default;

void ImportsView::render() {
    if (need_refresh_) {
        rebuild_modules();
        need_refresh_ = false;
    }

    render_toolbar();
    ImGui::Separator();
    render_tree();
}

void ImportsView::select_address(Address address) {
    selected_address_ = address;
}

void ImportsView::refresh() {
    need_refresh_ = true;
}

void ImportsView::render_toolbar() {
    // Search box
    ImGui::SetNextItemWidth(200);
    if (ImGui::InputTextWithHint("##filter", "Filter imports...", filter_text_, sizeof(filter_text_))) {
        filter_string_ = filter_text_;
        // Force tree rebuild to apply filter
        rebuild_modules();
    }

    // Count total imports
    std::size_t total_imports = 0;
    std::size_t filtered_imports = 0;
    for (const auto& mod : modules_) {
        filtered_imports += mod.imports.size();
    }

    // Get total from symbol table
    app_->symbols().for_each([&total_imports](const analysis::Symbol& sym) {
        if (sym.type == analysis::SymbolType::Import) {
            total_imports++;
        }
    });

    ImGui::SameLine();
    ImGui::Text("%zu / %zu imports", filtered_imports, total_imports);
}

void ImportsView::render_tree() {
    // IDA-style tree with columns: Address | Ordinal | Name
    ImGuiTableFlags table_flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;

    if (ImGui::BeginTable("ImportsTable", 3, table_flags)) {
        // Setup columns
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Ordinal", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        for (auto& mod : modules_) {
            if (mod.imports.empty()) continue;

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);

            // Tree node for DLL
            ImGuiTreeNodeFlags node_flags = ImGuiTreeNodeFlags_SpanFullWidth;
            if (mod.expanded) {
                node_flags |= ImGuiTreeNodeFlags_DefaultOpen;
            }

            bool node_open = ImGui::TreeNodeEx(mod.name.c_str(), node_flags);
            mod.expanded = node_open;

            if (node_open) {
                // Render imports under this DLL
                for (const auto& imp : mod.imports) {
                    ImGui::TableNextRow();
                    bool is_selected = (imp.address == selected_address_);

                    ImGui::PushID(static_cast<int>(imp.address));

                    // Address column
                    ImGui::TableSetColumnIndex(0);
                    char addr_str[32];
                    snprintf(addr_str, sizeof(addr_str), "%016llX",
                        static_cast<unsigned long long>(imp.address));

                    if (ImGui::Selectable(addr_str, is_selected,
                        ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                        selected_address_ = imp.address;
                        if (on_select_) {
                            on_select_(imp.address);
                        }
                        if (ImGui::IsMouseDoubleClicked(0)) {
                            app_->navigate_to(imp.address);
                        }
                    }

                    // Context menu
                    if (ImGui::BeginPopupContextItem()) {
                        ImGui::Text("Import: %s", imp.name.c_str());
                        ImGui::Separator();

                        if (ImGui::MenuItem("Go to")) {
                            app_->navigate_to(imp.address);
                        }

                        if (ImGui::MenuItem("Copy Address")) {
                            auto addr_copy = std::format("0x{:016X}", imp.address);
                            ImGui::SetClipboardText(addr_copy.c_str());
                        }

                        if (ImGui::MenuItem("Copy Name")) {
                            ImGui::SetClipboardText(imp.name.c_str());
                        }

                        ImGui::EndPopup();
                    }

                    // Ordinal column
                    ImGui::TableSetColumnIndex(1);
                    if (imp.by_ordinal || imp.ordinal > 0) {
                        ImGui::Text("%u", imp.ordinal);
                    }

                    // Name column
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(imp.name.c_str());

                    ImGui::PopID();
                }
                ImGui::TreePop();
            }
        }

        ImGui::EndTable();
    }
}

void ImportsView::rebuild_modules() {
    modules_.clear();

    // Group imports by module (DLL)
    std::map<std::string, std::vector<ImportEntry>> module_map;

    app_->symbols().for_each([this, &module_map](const analysis::Symbol& sym) {
        if (sym.type != analysis::SymbolType::Import) return;

        // Apply name filter
        if (!filter_string_.empty()) {
            bool matches = (sym.name.find(filter_string_) != std::string::npos) ||
                           (sym.module_name.find(filter_string_) != std::string::npos);
            if (!matches) return;
        }

        ImportEntry entry;
        entry.address = sym.address;
        entry.name = sym.name;
        entry.ordinal = sym.ordinal;
        entry.by_ordinal = sym.name.empty() || sym.name.find("Ordinal_") != std::string::npos;

        std::string module_name = sym.module_name;
        if (module_name.empty()) {
            module_name = "<unknown>";
        }

        module_map[module_name].push_back(entry);
    });

    // Convert to vector and sort
    for (auto& [name, imports] : module_map) {
        ImportModule mod;
        mod.name = name;

        // Sort imports by name
        std::sort(imports.begin(), imports.end(),
            [](const ImportEntry& a, const ImportEntry& b) {
                return a.name < b.name;
            });

        mod.imports = std::move(imports);
        mod.expanded = true;
        modules_.push_back(std::move(mod));
    }

    // Sort modules alphabetically
    std::sort(modules_.begin(), modules_.end(),
        [](const ImportModule& a, const ImportModule& b) {
            return a.name < b.name;
        });
}

} // namespace picanha::ui
