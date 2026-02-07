#pragma once

#ifdef PICANHA_ENABLE_LLVM

#include <picanha/lift/lifted_function.hpp>
#include <imgui.h>
#include <memory>
#include <string>
#include <vector>

namespace picanha::ui {

class Application;

// Configuration for IR view syntax highlighting
struct IRViewConfig {
    bool show_line_numbers{true};
    bool word_wrap{false};
    float font_size{14.0f};

    // LLVM IR syntax colors (ABGR format)
    ImU32 color_keyword{0xFFFF9040};     // define, declare, br, ret, call
    ImU32 color_type{0xFF40CCFF};        // i32, i64, ptr, void
    ImU32 color_register{0xFF40FF40};    // %reg0, %1
    ImU32 color_label{0xFFFF4040};       // label:
    ImU32 color_comment{0xFF808080};     // ; comments
    ImU32 color_string{0xFF40FFFF};      // "strings"
    ImU32 color_number{0xFFFFFF40};      // numeric constants
    ImU32 color_default{0xFFFFFFFF};     // default text
};

// View for displaying LLVM IR
class IRView {
public:
    explicit IRView(Application* app);
    ~IRView();

    // Render the view
    void render();

    // Set the function to display
    void set_function(std::shared_ptr<::picanha::lift::LiftedFunction> func);
    void clear();

    // Configuration
    [[nodiscard]] IRViewConfig& config() { return config_; }
    [[nodiscard]] const IRViewConfig& config() const { return config_; }

    // Status
    [[nodiscard]] bool has_content() const { return current_function_ != nullptr; }
    [[nodiscard]] const std::string& current_function_name() const;

private:
    void render_ir_text();
    void render_line(const std::string& line, std::size_t line_num);
    void render_token(const std::string& token);
    bool is_keyword(const std::string& token) const;
    bool is_type(const std::string& token) const;

    Application* app_;
    IRViewConfig config_;
    std::shared_ptr<::picanha::lift::LiftedFunction> current_function_;

    // Parsed lines for rendering
    std::vector<std::string> lines_;
    bool lines_dirty_{true};

    // Scroll state
    float scroll_y_{0.0f};
    bool scroll_to_top_{false};
};

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
