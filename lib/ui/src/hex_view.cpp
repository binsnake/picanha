#include <picanha/ui/hex_view.hpp>
#include <picanha/ui/app.hpp>
#include <imgui.h>

#include <algorithm>
#include <format>
#include <cstring>

namespace picanha::ui {

HexView::HexView(Application* app)
    : app_(app)
{
}

HexView::~HexView() = default;

void HexView::render() {
    handle_keyboard();

    // Toolbar
    render_header();

    ImGui::Separator();

    // Main hex content
    ImGuiWindowFlags flags = ImGuiWindowFlags_HorizontalScrollbar;

    // Calculate content width - ensure inspector doesn't take more than 40% of available width
    float available_width = ImGui::GetContentRegionAvail().x;
    float inspector_width = show_inspector_ ? std::min(350.0f, available_width * 0.4f) : 0.0f;
    float content_width = show_inspector_ ? (available_width - inspector_width - 8.0f) : 0.0f;

    if (ImGui::BeginChild("HexContent", ImVec2(content_width, 0), ImGuiChildFlags_None, flags)) {
        if (view_size_ > 0) {
            float line_height = ImGui::GetTextLineHeightWithSpacing();
            std::size_t total_rows = (view_size_ + config_.bytes_per_row - 1) / config_.bytes_per_row;

            // Virtual scrolling
            float scroll_y = ImGui::GetScrollY();
            float window_height = ImGui::GetWindowHeight();

            std::size_t first_row = static_cast<std::size_t>(scroll_y / line_height);
            std::size_t visible_rows = static_cast<std::size_t>(window_height / line_height) + 2;

            first_row = std::min(first_row, total_rows > 0 ? total_rows - 1 : 0);
            std::size_t last_row = std::min(first_row + visible_rows, total_rows);

            // Spacer before visible content
            ImGui::Dummy(ImVec2(0, first_row * line_height));

            // Render visible rows
            for (std::size_t row = first_row; row < last_row; ++row) {
                Address row_addr = view_start_ + row * config_.bytes_per_row;
                render_row(row_addr);
            }

            // Spacer after visible content
            float remaining_height = (total_rows - last_row) * line_height;
            if (remaining_height > 0) {
                ImGui::Dummy(ImVec2(0, remaining_height));
            }

            visible_rows_ = static_cast<int>(visible_rows);
        } else {
            ImGui::TextDisabled("No data to display");
            ImGui::TextDisabled("Load a binary to view hex data");
        }

        handle_mouse();
    }
    ImGui::EndChild();

    // Data inspector panel
    if (show_inspector_) {
        ImGui::SameLine();
        if (ImGui::BeginChild("Inspector", ImVec2(inspector_width, 0), ImGuiChildFlags_Borders)) {
            render_data_inspector();
        }
        ImGui::EndChild();
    }
}

void HexView::goto_address(Address address) {
    // Clamp address to valid range
    if (view_size_ == 0) return;

    if (address < view_start_) {
        address = view_start_;
    } else if (address >= view_start_ + view_size_) {
        address = view_start_ + view_size_ - 1;
    }

    cursor_ = address;
    selection_start_ = address;
    selection_end_ = address;
    ensure_cursor_visible();
}

void HexView::scroll_to_address(Address address) {
    goto_address(address);
}

void HexView::set_view_range(Address start, Size size) {
    view_start_ = start;
    view_size_ = size;
    cursor_ = start;
    clear_selection();
}

void HexView::select_byte(Address address) {
    if (address >= view_start_ && address < view_start_ + view_size_) {
        cursor_ = address;
        selection_start_ = address;
        selection_end_ = address;
    }
}

void HexView::select_range(Address start, Address end) {
    selection_start_ = start;
    selection_end_ = end;
    cursor_ = end;
}

void HexView::clear_selection() {
    selection_start_ = INVALID_ADDRESS;
    selection_end_ = INVALID_ADDRESS;
    selecting_ = false;
}

void HexView::highlight_range(Address start, Address end, ImU32 color) {
    highlights_.push_back({start, end, color});
}

void HexView::clear_highlights() {
    highlights_.clear();
}

std::uint8_t HexView::get_byte(Address address) const {
    auto binary = app_->binary();
    if (!binary) return 0;

    auto bytes = binary->read(address, 1);
    return (!bytes || bytes->empty()) ? 0 : (*bytes)[0];
}

std::uint16_t HexView::get_word(Address address) const {
    auto binary = app_->binary();
    if (!binary) return 0;

    auto bytes = binary->read(address, 2);
    if (!bytes || bytes->size() < 2) return 0;

    std::uint16_t value;
    std::memcpy(&value, bytes->data(), sizeof(value));
    return value;
}

std::uint32_t HexView::get_dword(Address address) const {
    auto binary = app_->binary();
    if (!binary) return 0;

    auto bytes = binary->read(address, 4);
    if (!bytes || bytes->size() < 4) return 0;

    std::uint32_t value;
    std::memcpy(&value, bytes->data(), sizeof(value));
    return value;
}

std::uint64_t HexView::get_qword(Address address) const {
    auto binary = app_->binary();
    if (!binary) return 0;

    auto bytes = binary->read(address, 8);
    if (!bytes || bytes->size() < 8) return 0;

    std::uint64_t value;
    std::memcpy(&value, bytes->data(), sizeof(value));
    return value;
}

std::string HexView::get_string(Address address, std::size_t max_len) const {
    auto binary = app_->binary();
    if (!binary) return "";

    auto bytes = binary->read(address, max_len);
    if (!bytes) return "";

    std::string result;
    result.reserve(bytes->size());

    for (auto b : *bytes) {
        if (b == 0) break;
        result += static_cast<char>(b);
    }

    return result;
}

void HexView::render_header() {
    if (ImGui::Button("Go to...")) {
        // TODO: Open goto dialog
    }
    ImGui::SameLine();

    ImGui::SetNextItemWidth(80);
    if (ImGui::Combo("##bytes_per_row", &config_.bytes_per_row,
        "8\0" "16\0" "32\0")) {
        // Map index to value
        static const int values[] = {8, 16, 32};
        config_.bytes_per_row = values[config_.bytes_per_row < 3 ? config_.bytes_per_row : 1];
    }
    ImGui::SameLine();

    ImGui::Checkbox("ASCII", &config_.show_ascii);
    ImGui::SameLine();
    ImGui::Checkbox("Inspector", &show_inspector_);

    // Address display
    ImGui::SameLine(ImGui::GetWindowWidth() - 200);
    if (cursor_ != INVALID_ADDRESS) {
        ImGui::Text("Cursor: %s", format_address(cursor_).c_str());
    }
}

void HexView::render_row(Address row_start) {
    auto binary = app_->binary();
    if (!binary) return;

    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetCursorScreenPos();
    float char_width = ImGui::CalcTextSize("0").x;
    float spacing = ImGui::GetStyle().ItemSpacing.x;

    float x = pos.x;

    // Render address
    if (config_.show_address) {
        std::string addr_str = format_address(row_start);
        draw_list->AddText(ImVec2(x, pos.y), config_.color_address, addr_str.c_str());
        x += addr_str.length() * char_width + spacing * 2;
    }

    // Read bytes for this row
    Size bytes_to_read = std::min(static_cast<Size>(config_.bytes_per_row),
                                   view_size_ - (row_start - view_start_));
    auto bytes_opt = binary->read(row_start, bytes_to_read);

    // Create a vector for bytes, fill with 0 if read failed
    std::vector<std::uint8_t> bytes_storage;
    bool read_failed = !bytes_opt;
    if (bytes_opt) {
        bytes_storage.assign(bytes_opt->begin(), bytes_opt->end());
    } else {
        bytes_storage.resize(bytes_to_read, 0);
    }
    const auto& bytes = bytes_storage;

    // Render hex bytes
    float hex_start_x = x;
    for (std::size_t i = 0; i < static_cast<std::size_t>(config_.bytes_per_row); ++i) {
        Address byte_addr = row_start + i;

        // Check if in selection
        bool in_selection = has_selection() &&
            byte_addr >= std::min(selection_start_, selection_end_) &&
            byte_addr <= std::max(selection_start_, selection_end_);

        // Check if cursor
        bool is_cursor = (byte_addr == cursor_);

        // Check highlights
        ImU32 highlight_color = 0;
        for (const auto& h : highlights_) {
            if (byte_addr >= h.start && byte_addr <= h.end) {
                highlight_color = h.color;
                break;
            }
        }

        // Background
        if (is_cursor) {
            ImVec2 rect_min(x, pos.y);
            ImVec2 rect_max(x + char_width * 2 + 4, pos.y + ImGui::GetTextLineHeight());
            draw_list->AddRectFilled(rect_min, rect_max, config_.color_highlight);
        } else if (in_selection) {
            ImVec2 rect_min(x, pos.y);
            ImVec2 rect_max(x + char_width * 2 + 4, pos.y + ImGui::GetTextLineHeight());
            draw_list->AddRectFilled(rect_min, rect_max, config_.color_selection);
        } else if (highlight_color != 0) {
            ImVec2 rect_min(x, pos.y);
            ImVec2 rect_max(x + char_width * 2 + 4, pos.y + ImGui::GetTextLineHeight());
            draw_list->AddRectFilled(rect_min, rect_max, highlight_color);
        }

        // Hex text
        if (i < bytes.size()) {
            if (read_failed) {
                // Show ?? for unreadable bytes
                draw_list->AddText(ImVec2(x, pos.y), config_.color_non_printable, "??");
            } else {
                std::string hex = config_.uppercase_hex ?
                    std::format("{:02X}", bytes[i]) :
                    std::format("{:02x}", bytes[i]);
                draw_list->AddText(ImVec2(x, pos.y), config_.color_hex, hex.c_str());
            }
        } else {
            draw_list->AddText(ImVec2(x, pos.y), config_.color_non_printable, "  ");
        }

        x += char_width * 2 + (i % 8 == 7 ? spacing * 2 : spacing);
    }

    // Render ASCII
    if (config_.show_ascii) {
        x += spacing * 2;

        for (std::size_t i = 0; i < bytes.size(); ++i) {
            Address byte_addr = row_start + i;

            bool in_selection = has_selection() &&
                byte_addr >= std::min(selection_start_, selection_end_) &&
                byte_addr <= std::max(selection_start_, selection_end_);

            bool is_cursor = (byte_addr == cursor_);

            // Background
            if (is_cursor) {
                ImVec2 rect_min(x, pos.y);
                ImVec2 rect_max(x + char_width, pos.y + ImGui::GetTextLineHeight());
                draw_list->AddRectFilled(rect_min, rect_max, config_.color_highlight);
            } else if (in_selection) {
                ImVec2 rect_min(x, pos.y);
                ImVec2 rect_max(x + char_width, pos.y + ImGui::GetTextLineHeight());
                draw_list->AddRectFilled(rect_min, rect_max, config_.color_selection);
            }

            char c = read_failed ? '?' : to_printable(bytes[i]);
            char str[2] = {c, 0};
            ImU32 color = (c == '.' || c == '?') ? config_.color_non_printable : config_.color_ascii;
            draw_list->AddText(ImVec2(x, pos.y), color, str);

            x += char_width;
        }
    }

    // Move to next line
    ImGui::Dummy(ImVec2(x - pos.x, ImGui::GetTextLineHeight()));
}

void HexView::render_address(Address address) {
    ImGui::TextColored(ImColor(config_.color_address).Value, "%s", format_address(address).c_str());
}

void HexView::render_hex_bytes(Address row_start) {
    // Implemented inline in render_row
    (void)row_start;
}

void HexView::render_ascii(Address row_start) {
    // Implemented inline in render_row
    (void)row_start;
}

void HexView::render_data_inspector() {
    ImGui::Text("Data Inspector");
    ImGui::Separator();

    if (cursor_ == INVALID_ADDRESS) {
        ImGui::TextDisabled("No data selected");
        return;
    }

    ImGui::Text("Address: %s", format_address(cursor_).c_str());
    ImGui::Separator();

    // Type selector
    const char* type_names[] = {"Byte", "Word", "Dword", "Qword", "Float", "Double", "String", "Unicode"};
    int type_index = static_cast<int>(inspector_type_);
    if (ImGui::Combo("Type", &type_index, type_names, 8)) {
        inspector_type_ = static_cast<DataType>(type_index);
    }

    ImGui::Separator();

    // Values
    auto binary = app_->binary();
    if (!binary) return;

    std::uint8_t byte_val = get_byte(cursor_);
    std::uint16_t word_val = get_word(cursor_);
    std::uint32_t dword_val = get_dword(cursor_);
    std::uint64_t qword_val = get_qword(cursor_);

    ImGui::Text("Byte:   %3u  0x%02X  '%c'", byte_val, byte_val, to_printable(byte_val));
    ImGui::Text("Word:   %5u  0x%04X", word_val, word_val);
    ImGui::Text("Dword:  %10u  0x%08X", dword_val, dword_val);
    ImGui::Text("Qword:  %llu", static_cast<unsigned long long>(qword_val));
    ImGui::Text("        0x%016llX", static_cast<unsigned long long>(qword_val));

    ImGui::Separator();

    // Signed interpretations
    ImGui::Text("Signed:");
    ImGui::Text("  Int8:   %d", static_cast<std::int8_t>(byte_val));
    ImGui::Text("  Int16:  %d", static_cast<std::int16_t>(word_val));
    ImGui::Text("  Int32:  %d", static_cast<std::int32_t>(dword_val));
    ImGui::Text("  Int64:  %lld", static_cast<long long>(static_cast<std::int64_t>(qword_val)));

    ImGui::Separator();

    // Float interpretations
    float float_val;
    double double_val;
    std::memcpy(&float_val, &dword_val, sizeof(float_val));
    std::memcpy(&double_val, &qword_val, sizeof(double_val));
    ImGui::Text("Float:  %g", float_val);
    ImGui::Text("Double: %g", double_val);

    ImGui::Separator();

    // String preview
    std::string str = get_string(cursor_, 64);
    if (!str.empty()) {
        ImGui::Text("String: \"%s\"", str.c_str());
    }
}

void HexView::handle_keyboard() {
    if (!ImGui::IsWindowFocused()) return;

    ImGuiIO& io = ImGui::GetIO();
    int bytes_per_row = config_.bytes_per_row;

    if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) {
        if (cursor_ > view_start_) {
            cursor_--;
            if (!io.KeyShift) clear_selection();
            else if (selection_start_ == INVALID_ADDRESS) selection_start_ = cursor_ + 1;
            selection_end_ = cursor_;
            ensure_cursor_visible();
        }
    }
    if (ImGui::IsKeyPressed(ImGuiKey_RightArrow)) {
        if (cursor_ < view_start_ + view_size_ - 1) {
            cursor_++;
            if (!io.KeyShift) clear_selection();
            else if (selection_start_ == INVALID_ADDRESS) selection_start_ = cursor_ - 1;
            selection_end_ = cursor_;
            ensure_cursor_visible();
        }
    }
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
        if (cursor_ >= view_start_ + bytes_per_row) {
            cursor_ -= bytes_per_row;
            if (!io.KeyShift) clear_selection();
            else if (selection_start_ == INVALID_ADDRESS) selection_start_ = cursor_ + bytes_per_row;
            selection_end_ = cursor_;
            ensure_cursor_visible();
        }
    }
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) {
        if (cursor_ + bytes_per_row < view_start_ + view_size_) {
            cursor_ += bytes_per_row;
            if (!io.KeyShift) clear_selection();
            else if (selection_start_ == INVALID_ADDRESS) selection_start_ = cursor_ - bytes_per_row;
            selection_end_ = cursor_;
            ensure_cursor_visible();
        }
    }
    if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) {
        Size page_bytes = bytes_per_row * visible_rows_;
        cursor_ = cursor_ > view_start_ + page_bytes ? cursor_ - page_bytes : view_start_;
        if (!io.KeyShift) clear_selection();
        ensure_cursor_visible();
    }
    if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) {
        Size page_bytes = bytes_per_row * visible_rows_;
        cursor_ = std::min(cursor_ + page_bytes, view_start_ + view_size_ - 1);
        if (!io.KeyShift) clear_selection();
        ensure_cursor_visible();
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Home)) {
        if (io.KeyCtrl) {
            cursor_ = view_start_;
        } else {
            // Go to start of current row
            cursor_ = view_start_ + ((cursor_ - view_start_) / bytes_per_row) * bytes_per_row;
        }
        if (!io.KeyShift) clear_selection();
        ensure_cursor_visible();
    }
    if (ImGui::IsKeyPressed(ImGuiKey_End)) {
        if (io.KeyCtrl) {
            cursor_ = view_start_ + view_size_ - 1;
        } else {
            // Go to end of current row
            Address row_start = view_start_ + ((cursor_ - view_start_) / bytes_per_row) * bytes_per_row;
            cursor_ = std::min(row_start + bytes_per_row - 1, view_start_ + view_size_ - 1);
        }
        if (!io.KeyShift) clear_selection();
        ensure_cursor_visible();
    }

    // Copy
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C)) {
        if (has_selection()) {
            Address start = std::min(selection_start_, selection_end_);
            Address end = std::max(selection_start_, selection_end_);
            Size len = end - start + 1;

            auto binary = app_->binary();
            if (binary) {
                auto bytes_opt = binary->read(start, len);
                if (bytes_opt) {
                    std::string hex;
                    for (auto b : *bytes_opt) {
                        hex += std::format("{:02X} ", b);
                    }
                    ImGui::SetClipboardText(hex.c_str());
                }
            }
        }
    }

    // Select all
    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A)) {
        selection_start_ = view_start_;
        selection_end_ = view_start_ + view_size_ - 1;
    }

    // Go to address
    if (ImGui::IsKeyPressed(ImGuiKey_G)) {
        // TODO: Open goto dialog
    }
}

void HexView::handle_mouse() {
    if (!ImGui::IsWindowHovered()) return;

    ImGuiIO& io = ImGui::GetIO();
    ImVec2 mouse_pos = ImGui::GetMousePos();
    ImVec2 window_pos = ImGui::GetWindowPos();

    // Calculate which byte was clicked
    float char_width = ImGui::CalcTextSize("0").x;
    float line_height = ImGui::GetTextLineHeightWithSpacing();
    float scroll_y = ImGui::GetScrollY();

    // Offset for address column
    float addr_width = config_.show_address ? (config_.address_width * char_width + 16) : 0;

    float rel_x = mouse_pos.x - window_pos.x - addr_width;
    float rel_y = mouse_pos.y - window_pos.y + scroll_y;

    if (rel_x < 0) return;

    // Calculate byte position
    float byte_width = char_width * 2 + ImGui::GetStyle().ItemSpacing.x;
    std::size_t col = static_cast<std::size_t>(rel_x / byte_width);
    std::size_t row = static_cast<std::size_t>(rel_y / line_height);

    if (col >= static_cast<std::size_t>(config_.bytes_per_row)) return;

    Address byte_addr = view_start_ + row * config_.bytes_per_row + col;
    if (byte_addr >= view_start_ + view_size_) return;

    if (ImGui::IsMouseClicked(0)) {
        cursor_ = byte_addr;
        if (!io.KeyShift) {
            clear_selection();
        }
        selection_start_ = byte_addr;
        selection_end_ = byte_addr;
        selecting_ = true;
    }

    if (ImGui::IsMouseDragging(0) && selecting_) {
        selection_end_ = byte_addr;
        cursor_ = byte_addr;
    }

    if (ImGui::IsMouseReleased(0)) {
        selecting_ = false;
    }
}

void HexView::ensure_cursor_visible() {
    // Calculate cursor row
    std::size_t cursor_row = (cursor_ - view_start_) / config_.bytes_per_row;
    float line_height = ImGui::GetTextLineHeightWithSpacing();
    float target_y = cursor_row * line_height;

    float scroll_y = ImGui::GetScrollY();
    float window_height = ImGui::GetWindowHeight();

    if (target_y < scroll_y) {
        ImGui::SetScrollY(target_y);
    } else if (target_y + line_height > scroll_y + window_height) {
        ImGui::SetScrollY(target_y - window_height + line_height);
    }
}

void HexView::update_visible_rows() {
    float line_height = ImGui::GetTextLineHeightWithSpacing();
    float window_height = ImGui::GetWindowHeight();
    visible_rows_ = static_cast<int>(window_height / line_height);
}

std::string HexView::format_address(Address address) const {
    if (config_.address_width == 8) {
        return std::format("{:08X}", static_cast<std::uint32_t>(address));
    }
    return std::format("{:016X}", address);
}

char HexView::to_printable(std::uint8_t byte) const {
    if (byte >= 32 && byte < 127) {
        return static_cast<char>(byte);
    }
    return '.';
}

} // namespace picanha::ui
