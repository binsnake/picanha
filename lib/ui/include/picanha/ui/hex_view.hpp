#pragma once

#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>
#include <imgui.h>
#include <memory>
#include <vector>
#include <string>
#include <optional>

namespace picanha::ui {

class Application;

// Hex view configuration
struct HexViewConfig {
    int bytes_per_row{16};
    bool show_ascii{true};
    bool show_address{true};
    bool uppercase_hex{true};
    int address_width{16};
    ImU32 color_address{0xFF808080};
    ImU32 color_hex{0xFFFFFFFF};
    ImU32 color_ascii{0xFF40FF40};
    ImU32 color_non_printable{0xFF606060};
    ImU32 color_selection{0x40FFFFFF};
    ImU32 color_highlight{0x400000FF};
    ImU32 color_modified{0xFFFF4040};
};

// Data type for interpretation
enum class DataType {
    Byte,
    Word,          // 2 bytes
    Dword,         // 4 bytes
    Qword,         // 8 bytes
    Float,
    Double,
    String,
    Unicode,
};

// Hex editor/viewer
class HexView {
public:
    explicit HexView(Application* app);
    ~HexView();

    // Rendering
    void render();

    // Navigation
    void goto_address(Address address);
    void scroll_to_address(Address address);
    void set_view_range(Address start, Size size);

    // Selection
    void select_byte(Address address);
    void select_range(Address start, Address end);
    void clear_selection();
    [[nodiscard]] Address selection_start() const { return selection_start_; }
    [[nodiscard]] Address selection_end() const { return selection_end_; }
    [[nodiscard]] bool has_selection() const { return selection_start_ != INVALID_ADDRESS; }

    // Highlighting (for search results, etc.)
    void highlight_range(Address start, Address end, ImU32 color);
    void clear_highlights();

    // Data interpretation at cursor
    [[nodiscard]] std::uint8_t get_byte(Address address) const;
    [[nodiscard]] std::uint16_t get_word(Address address) const;
    [[nodiscard]] std::uint32_t get_dword(Address address) const;
    [[nodiscard]] std::uint64_t get_qword(Address address) const;
    [[nodiscard]] std::string get_string(Address address, std::size_t max_len = 256) const;

    // Configuration
    [[nodiscard]] HexViewConfig& config() { return config_; }
    [[nodiscard]] const HexViewConfig& config() const { return config_; }

    // View state
    [[nodiscard]] Address view_start() const { return view_start_; }
    [[nodiscard]] Size view_size() const { return view_size_; }
    [[nodiscard]] Address cursor() const { return cursor_; }

private:
    // Rendering helpers
    void render_header();
    void render_row(Address row_start);
    void render_address(Address address);
    void render_hex_bytes(Address row_start);
    void render_ascii(Address row_start);
    void render_data_inspector();

    // Input handling
    void handle_keyboard();
    void handle_mouse();

    // Scrolling
    void ensure_cursor_visible();
    void update_visible_rows();

    // Formatting
    std::string format_address(Address address) const;
    char to_printable(std::uint8_t byte) const;

    Application* app_;
    HexViewConfig config_;

    // View state
    Address view_start_{0};
    Size view_size_{0};
    Address cursor_{0};

    // Selection
    Address selection_start_{INVALID_ADDRESS};
    Address selection_end_{INVALID_ADDRESS};
    bool selecting_{false};

    // Highlights
    struct Highlight {
        Address start;
        Address end;
        ImU32 color;
    };
    std::vector<Highlight> highlights_;

    // Scroll state
    float scroll_y_{0.0f};
    int visible_rows_{0};

    // Data inspector
    bool show_inspector_{true};
    DataType inspector_type_{DataType::Qword};

    // Search
    std::string search_hex_;
    std::string search_text_;
    bool search_open_{false};
};

} // namespace picanha::ui
