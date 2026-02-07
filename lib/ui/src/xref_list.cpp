#include <picanha/ui/xref_list.hpp>
#include <picanha/ui/app.hpp>
#include <imgui.h>

#include <algorithm>
#include <format>

namespace picanha::ui {

XRefList::XRefList(Application* app)
    : app_(app)
{
}

XRefList::~XRefList() = default;

void XRefList::render() {
    if (need_refresh_) {
        rebuild_entries();
        need_refresh_ = false;
    }

    render_header();
    ImGui::Separator();
    render_table();
    render_context_menu();
}

void XRefList::set_target(Address address, XRefMode mode) {
    target_ = address;
    mode_ = mode;
    need_refresh_ = true;
}

void XRefList::select_xref(std::size_t index) {
    if (index < filtered_indices_.size()) {
        selected_index_ = index;
    }
}

void XRefList::apply_filter() {
    filtered_indices_.clear();

    for (std::size_t i = 0; i < entries_.size(); ++i) {
        const auto& entry = entries_[i];

        // Type filter
        switch (entry.type) {
            case analysis::XRefType::Call:
                if (!filter_.show_calls) continue;
                break;
            case analysis::XRefType::Jump:
            case analysis::XRefType::ConditionalJump:
                if (!filter_.show_jumps) continue;
                break;
            case analysis::XRefType::Read:
                if (!filter_.show_reads) continue;
                break;
            case analysis::XRefType::Write:
                if (!filter_.show_writes) continue;
                break;
            case analysis::XRefType::ReadWrite:
            case analysis::XRefType::Offset:
                if (!filter_.show_data) continue;
                break;
            default:
                break;
        }

        filtered_indices_.push_back(i);
    }
}

void XRefList::refresh() {
    need_refresh_ = true;
}

void XRefList::render_header() {
    if (target_ == INVALID_ADDRESS) {
        ImGui::TextDisabled("No target address selected");
        return;
    }

    auto mode_str = (mode_ == XRefMode::ToAddress) ? "to" :
                    (mode_ == XRefMode::FromAddress) ? "from" : "to/from";
    ImGui::Text("XRefs %s 0x%016llX", mode_str, static_cast<unsigned long long>(target_));

    ImGui::SameLine();
    ImGui::Text("(%zu references)", filtered_indices_.size());

    // Mode selector
    ImGui::SameLine(ImGui::GetWindowWidth() - 150);
    const char* mode_names[] = {"To Address", "From Address", "Both"};
    int mode_index = static_cast<int>(mode_);
    ImGui::SetNextItemWidth(100);
    if (ImGui::Combo("##mode", &mode_index, mode_names, 3)) {
        mode_ = static_cast<XRefMode>(mode_index);
        need_refresh_ = true;
    }
}

void XRefList::render_table() {
    if (target_ == INVALID_ADDRESS) {
        return;
    }

    ImGuiTableFlags flags = ImGuiTableFlags_Resizable |
        ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY;

    if (ImGui::BeginTable("XRefsTable", 4, flags)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("From", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("To", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        // Render rows
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(filtered_indices_.size()));

        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                std::size_t entry_idx = filtered_indices_[row];
                const auto& entry = entries_[entry_idx];

                ImGui::TableNextRow();

                bool is_selected = (static_cast<std::size_t>(row) == selected_index_);

                // From address
                ImGui::TableNextColumn();
                ImGuiSelectableFlags selectable_flags = ImGuiSelectableFlags_SpanAllColumns |
                    ImGuiSelectableFlags_AllowOverlap;

                if (ImGui::Selectable(std::format("0x{:016X}", entry.from).c_str(),
                    is_selected, selectable_flags)) {
                    selected_index_ = static_cast<std::size_t>(row);
                }

                if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
                    // Navigate to 'from' address
                    if (on_navigate_) {
                        on_navigate_(entry.from);
                    }
                }

                // To address
                ImGui::TableNextColumn();
                ImGui::Text("0x%016llX", static_cast<unsigned long long>(entry.to));

                // Type with color
                ImGui::TableNextColumn();
                ImU32 color = type_color(entry.type);
                ImGui::TextColored(ImColor(color).Value, "%s", type_name(entry.type));

                // Name (from function/symbol)
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(entry.from_name.c_str());
            }
        }

        ImGui::EndTable();
    }
}

void XRefList::render_context_menu() {
    if (ImGui::BeginPopupContextItem("XRefContextMenu")) {
        if (selected_index_ < filtered_indices_.size()) {
            const auto& entry = entries_[filtered_indices_[selected_index_]];

            ImGui::Text("XRef: %s", type_name(entry.type));
            ImGui::Separator();

            if (ImGui::MenuItem("Go to Source")) {
                if (on_navigate_) {
                    on_navigate_(entry.from);
                }
            }

            if (ImGui::MenuItem("Go to Target")) {
                if (on_navigate_) {
                    on_navigate_(entry.to);
                }
            }

            ImGui::Separator();

            if (ImGui::MenuItem("Copy Source Address")) {
                auto addr_str = std::format("0x{:016X}", entry.from);
                ImGui::SetClipboardText(addr_str.c_str());
            }

            if (ImGui::MenuItem("Copy Target Address")) {
                auto addr_str = std::format("0x{:016X}", entry.to);
                ImGui::SetClipboardText(addr_str.c_str());
            }
        }
        ImGui::EndPopup();
    }
}

bool XRefList::passes_filter(const analysis::XRef& xref) const {
    switch (xref.type) {
        case analysis::XRefType::Call:
            return filter_.show_calls;
        case analysis::XRefType::Jump:
        case analysis::XRefType::ConditionalJump:
            return filter_.show_jumps;
        case analysis::XRefType::Read:
            return filter_.show_reads;
        case analysis::XRefType::Write:
            return filter_.show_writes;
        case analysis::XRefType::ReadWrite:
        case analysis::XRefType::Offset:
            return filter_.show_data;
        default:
            return true;
    }
}

void XRefList::rebuild_entries() {
    entries_.clear();

    if (target_ == INVALID_ADDRESS) return;

    // Get xrefs based on mode
    std::vector<analysis::XRef> xrefs;

    if (mode_ == XRefMode::ToAddress || mode_ == XRefMode::Both) {
        auto refs_to = app_->xrefs().get_refs_to(target_);
        xrefs.insert(xrefs.end(), refs_to.begin(), refs_to.end());
    }

    if (mode_ == XRefMode::FromAddress || mode_ == XRefMode::Both) {
        auto refs_from = app_->xrefs().get_refs_from(target_);
        xrefs.insert(xrefs.end(), refs_from.begin(), refs_from.end());
    }

    for (const auto& xref : xrefs) {
        entries_.push_back(make_entry(xref));
    }

    // Reset filter indices
    filtered_indices_.clear();
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        filtered_indices_.push_back(i);
    }

    apply_filter();
}

XRefEntry XRefList::make_entry(const analysis::XRef& xref) const {
    XRefEntry entry;
    entry.from = xref.from;
    entry.to = xref.to;
    entry.type = xref.type;

    // Look up names
    if (auto sym = app_->symbols().find_at(xref.from)) {
        entry.from_name = sym->name;
    } else {
        // Check if in a function
        for (const auto& func : app_->functions()) {
            if (xref.from >= func.start_address() &&
                xref.from < func.start_address() + func.size()) {
                entry.from_name = func.name().empty() ?
                    std::format("sub_{:X}", func.start_address()) : func.name();
                break;
            }
        }
    }

    if (auto sym = app_->symbols().find_at(xref.to)) {
        entry.to_name = sym->name;
    }

    return entry;
}

const char* XRefList::type_name(analysis::XRefType type) {
    switch (type) {
        case analysis::XRefType::Call: return "Call";
        case analysis::XRefType::Jump: return "Jump";
        case analysis::XRefType::ConditionalJump: return "CondJump";
        case analysis::XRefType::Read: return "Read";
        case analysis::XRefType::Write: return "Write";
        case analysis::XRefType::ReadWrite: return "Data";
        case analysis::XRefType::Offset: return "Offset";
        default: return "Unknown";
    }
}

ImU32 XRefList::type_color(analysis::XRefType type) {
    switch (type) {
        case analysis::XRefType::Call: return 0xFF4090FF;  // Blue
        case analysis::XRefType::Jump: return 0xFF40FF40;  // Green
        case analysis::XRefType::ConditionalJump: return 0xFF40FFFF;  // Cyan
        case analysis::XRefType::Read: return 0xFFFF9040;  // Orange
        case analysis::XRefType::Write: return 0xFFFF4040;  // Red
        case analysis::XRefType::ReadWrite: return 0xFFFFFF40;  // Yellow
        case analysis::XRefType::Offset: return 0xFFFF40FF;  // Magenta
        default: return 0xFFFFFFFF;  // White
    }
}

} // namespace picanha::ui
