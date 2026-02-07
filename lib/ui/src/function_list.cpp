#include <picanha/ui/function_list.hpp>
#include <picanha/ui/app.hpp>
#include <imgui.h>

#include <algorithm>
#include <format>

namespace picanha::ui {

FunctionList::FunctionList(Application* app)
    : app_(app)
{
}

FunctionList::~FunctionList() = default;

void FunctionList::render() {
    if (need_refresh_) {
        rebuild_entries();
        need_refresh_ = false;
    }

    render_toolbar();
    ImGui::Separator();
    render_table();
    // Context menu is handled per-item in render_table()
}

void FunctionList::select_function(FunctionId id) {
    selected_id_ = id;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].id == id) {
            selected_index_ = i;
            scroll_to_selected_ = true;
            break;
        }
    }
}

void FunctionList::select_address(Address address) {
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].address == address) {
            selected_index_ = i;
            selected_id_ = entries_[i].id;
            scroll_to_selected_ = true;
            break;
        }
    }
}

void FunctionList::apply_filter() {
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

        // Size filter
        if (entry.size < filter_.size_min || entry.size > filter_.size_max) {
            continue;
        }

        // Type and flag filters
        using Type = analysis::FunctionType;
        using Flags = analysis::FunctionFlags;
        bool is_import = entry.type == Type::Import;
        bool is_export = entry.type == Type::Export;
        bool is_thunk = entry.type == Type::Thunk;
        bool is_library = (entry.flags & Flags::IsLibrary) != Flags::None;
        bool is_noreturn = (entry.flags & Flags::NoReturn) != Flags::None;

        if (is_import && !filter_.show_imports) continue;
        if (is_export && !filter_.show_exports) continue;
        if (is_thunk && !filter_.show_thunks) continue;
        if (is_library && !filter_.show_library) continue;
        if (is_noreturn && !filter_.show_noreturn) continue;

        filtered_indices_.push_back(i);
    }

    sort_entries();
}

void FunctionList::refresh() {
    need_refresh_ = true;
}

void FunctionList::render_toolbar() {
    // Search box
    ImGui::SetNextItemWidth(200);
    if (ImGui::InputTextWithHint("##filter", "Filter functions...", filter_text_, sizeof(filter_text_))) {
        filter_.name_filter = filter_text_;
        apply_filter();
    }

    ImGui::SameLine();
    if (ImGui::Button("Filter...")) {
        filter_popup_open_ = true;
    }

    ImGui::SameLine();
    ImGui::Text("%zu / %zu functions", filtered_indices_.size(), entries_.size());

    // Filter popup
    if (filter_popup_open_) {
        render_filter_popup();
    }
}

void FunctionList::render_filter_popup() {
    ImGui::OpenPopup("Function Filter");

    if (ImGui::BeginPopupModal("Function Filter", &filter_popup_open_, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Show:");
        ImGui::Checkbox("Imports", &filter_.show_imports);
        ImGui::Checkbox("Exports", &filter_.show_exports);
        ImGui::Checkbox("Thunks", &filter_.show_thunks);
        ImGui::Checkbox("Library functions", &filter_.show_library);
        ImGui::Checkbox("No-return functions", &filter_.show_noreturn);

        ImGui::Separator();
        ImGui::Text("Size range:");

        int size_min = static_cast<int>(filter_.size_min);
        int size_max = filter_.size_max == INVALID_ADDRESS ? 0 : static_cast<int>(filter_.size_max);
        ImGui::InputInt("Min size", &size_min);
        ImGui::InputInt("Max size (0 = no limit)", &size_max);
        filter_.size_min = static_cast<Size>(std::max(0, size_min));
        filter_.size_max = size_max == 0 ? INVALID_ADDRESS : static_cast<Size>(size_max);

        ImGui::Separator();
        if (ImGui::Button("Apply", ImVec2(120, 0))) {
            apply_filter();
            filter_popup_open_ = false;
        }
        ImGui::SameLine();
        if (ImGui::Button("Reset", ImVec2(120, 0))) {
            filter_ = FunctionFilter{};
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

void FunctionList::render_table() {
    // IDA-style table with columns: Function name | Segment | Start
    ImGuiTableFlags table_flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
        ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV |
        ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp;

    if (ImGui::BeginTable("FunctionsTable", 3, table_flags)) {
        // Setup columns
        ImGui::TableSetupColumn("Function name", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthStretch, 0.5f);
        ImGui::TableSetupColumn("Segment", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("Start", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupScrollFreeze(0, 1);  // Freeze header row
        ImGui::TableHeadersRow();

        // Handle sorting
        if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs()) {
            if (sort_specs->SpecsDirty) {
                if (sort_specs->SpecsCount > 0) {
                    const ImGuiTableColumnSortSpecs& spec = sort_specs->Specs[0];
                    switch (spec.ColumnIndex) {
                        case 0: sort_column_ = FunctionSortColumn::Name; break;
                        case 1: sort_column_ = FunctionSortColumn::Address; break;  // Sort by address for segment
                        case 2: sort_column_ = FunctionSortColumn::Address; break;
                    }
                    sort_ascending_ = (spec.SortDirection == ImGuiSortDirection_Ascending);
                    sort_entries();
                }
                sort_specs->SpecsDirty = false;
            }
        }

        // Render rows with clipper for performance
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered_indices_.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                std::size_t entry_idx = filtered_indices_[row];
                const auto& entry = entries_[entry_idx];
                bool is_selected = (entry.id == selected_id_);

                ImGui::TableNextRow();
                ImGui::PushID(static_cast<int>(entry_idx));

                // Function name column
                ImGui::TableSetColumnIndex(0);
                if (ImGui::Selectable(entry.name.c_str(), is_selected,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    selected_id_ = entry.id;
                    selected_index_ = entry_idx;
                    if (on_select_) {
                        on_select_(entry.id);
                    }
                    if (ImGui::IsMouseDoubleClicked(0)) {
                        app_->navigate_to(entry.address);
                    }
                }

                // Tooltip with details
                if (ImGui::IsItemHovered()) {
                    ImGui::BeginTooltip();
                    ImGui::Text("Size: %zu bytes", entry.size);
                    ImGui::Text("Blocks: %zu", entry.block_count);
                    ImGui::Text("XRefs: %zu", entry.xref_count);
                    ImGui::EndTooltip();
                }

                // Context menu
                if (ImGui::BeginPopupContextItem()) {
                    ImGui::Text("Function: %s", entry.name.c_str());
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

                // Segment column
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(entry.segment.c_str());

                // Start address column
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%016llX", static_cast<unsigned long long>(entry.address));

                ImGui::PopID();
            }
        }

        // Handle scroll to selected
        if (scroll_to_selected_) {
            for (std::size_t i = 0; i < filtered_indices_.size(); ++i) {
                if (entries_[filtered_indices_[i]].id == selected_id_) {
                    ImGui::SetScrollY(clipper.ItemsHeight * static_cast<float>(i));
                    break;
                }
            }
            scroll_to_selected_ = false;
        }

        ImGui::EndTable();
    }
}

void FunctionList::render_context_menu() {
    if (ImGui::BeginPopupContextItem("FunctionContextMenu")) {
        if (selected_id_ != INVALID_FUNCTION_ID) {
            const auto& entry = entries_[selected_index_];

            ImGui::Text("Function: %s", entry.name.c_str());
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

            if (ImGui::MenuItem("Delete")) {
                // TODO: Confirm and delete function
            }
        }
        ImGui::EndPopup();
    }
}

void FunctionList::sort_entries() {
    std::sort(filtered_indices_.begin(), filtered_indices_.end(),
        [this](std::size_t a, std::size_t b) {
            const auto& ea = entries_[a];
            const auto& eb = entries_[b];

            int cmp = 0;
            switch (sort_column_) {
                case FunctionSortColumn::Address:
                    cmp = (ea.address < eb.address) ? -1 : (ea.address > eb.address) ? 1 : 0;
                    break;
                case FunctionSortColumn::Name:
                    cmp = ea.name.compare(eb.name);
                    break;
                case FunctionSortColumn::Size:
                    cmp = (ea.size < eb.size) ? -1 : (ea.size > eb.size) ? 1 : 0;
                    break;
                case FunctionSortColumn::BlockCount:
                    cmp = (ea.block_count < eb.block_count) ? -1 : (ea.block_count > eb.block_count) ? 1 : 0;
                    break;
                case FunctionSortColumn::XRefCount:
                    cmp = (ea.xref_count < eb.xref_count) ? -1 : (ea.xref_count > eb.xref_count) ? 1 : 0;
                    break;
            }

            return sort_ascending_ ? (cmp < 0) : (cmp > 0);
        });
}

bool FunctionList::passes_filter(const analysis::Function& func) const {
    // Basic name filter
    if (!filter_.name_filter.empty()) {
        if (func.name().find(filter_.name_filter) == std::string::npos) {
            return false;
        }
    }

    // Address filter
    if (func.start_address() < filter_.address_min ||
        func.start_address() > filter_.address_max) {
        return false;
    }

    // Size filter
    if (func.size() < filter_.size_min || func.size() > filter_.size_max) {
        return false;
    }

    return true;
}

void FunctionList::rebuild_entries() {
    entries_.clear();

    for (const auto& func : app_->functions()) {
        entries_.push_back(make_entry(func));
    }

    // Reset filter indices
    filtered_indices_.clear();
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        filtered_indices_.push_back(i);
    }

    apply_filter();
}

FunctionEntry FunctionList::make_entry(const analysis::Function& func) const {
    FunctionEntry entry;
    entry.id = func.id();
    entry.address = func.start_address();
    entry.name = func.name().empty() ?
        std::format("sub_{:X}", func.start_address()) : func.name();
    entry.size = func.size();
    entry.block_count = func.block_count();
    auto refs = app_->xrefs().get_refs_to(func.start_address());
    entry.xref_count = refs.size();
    entry.type = func.type();
    entry.flags = func.flags();

    // Find section containing this function
    if (auto binary = app_->binary()) {
        if (auto* section = binary->find_section(func.start_address())) {
            entry.segment = section->name;
        }
    }
    if (entry.segment.empty()) {
        entry.segment = ".text";  // Default fallback
    }

    return entry;
}

} // namespace picanha::ui
