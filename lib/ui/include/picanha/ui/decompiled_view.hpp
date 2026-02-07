#pragma once

#ifdef PICANHA_ENABLE_LLVM

#include <picanha/lift/lifted_function.hpp>
#include <imgui.h>
#include <memory>
#include <string>
#include <vector>

namespace picanha::ui {

class Application;

// Configuration for decompiled C view syntax highlighting
struct DecompiledViewConfig {
    bool show_line_numbers{true};
    bool word_wrap{false};
    float font_size{14.0f};

    // C syntax colors (ABGR format)
    ImU32 color_keyword{0xFFFF9040};     // if, else, while, for, return
    ImU32 color_type{0xFF40CCFF};        // int, void, char, struct
    ImU32 color_function{0xFF40FF90};    // function names
    ImU32 color_variable{0xFF40FF40};    // variables
    ImU32 color_comment{0xFF808080};     // // and /* */ comments
    ImU32 color_string{0xFF40FFFF};      // "strings"
    ImU32 color_number{0xFFFFFF40};      // numeric constants
    ImU32 color_operator{0xFFFFFFFF};    // operators
    ImU32 color_default{0xFFFFFFFF};     // default text
};

// View for displaying decompiled C code
class DecompiledView {
public:
    explicit DecompiledView(Application* app);
    ~DecompiledView();

    // Render the view
    void render();

    // Set the function to decompile and display
    void set_function(std::shared_ptr<::picanha::lift::LiftedFunction> func);
    void clear();

    // Force re-decompilation
    void refresh();

    // Configuration
    [[nodiscard]] DecompiledViewConfig& config() { return config_; }
    [[nodiscard]] const DecompiledViewConfig& config() const { return config_; }

    // Status
    [[nodiscard]] bool has_content() const { return !decompiled_code_.empty(); }
    [[nodiscard]] bool is_decompiling() const { return is_decompiling_; }
    [[nodiscard]] const std::string& error_message() const { return error_message_; }
    [[nodiscard]] const std::string& current_function_name() const;

private:
    void decompile_current();
    void render_code();
    void render_line(const std::string& line, std::size_t line_num);
    void render_token(const std::string& token);
    bool is_keyword(const std::string& token) const;
    bool is_type(const std::string& token) const;

    Application* app_;
    DecompiledViewConfig config_;
    std::shared_ptr<::picanha::lift::LiftedFunction> current_function_;

    // Decompiled code
    std::string decompiled_code_;
    std::vector<std::string> lines_;
    bool lines_dirty_{true};

    // Status
    bool is_decompiling_{false};
    std::string error_message_;
    std::string current_name_;

    // Scroll state
    float scroll_y_{0.0f};
    bool scroll_to_top_{false};
};

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
