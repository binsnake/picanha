#include <picanha/ui/decompiled_view.hpp>

#ifdef PICANHA_ENABLE_LLVM

#include <picanha/ui/app.hpp>
#include <picanha/lift/decompilation_service.hpp>
#include <picanha/lift/lifting_service.hpp>

#include <algorithm>
#include <sstream>
#include <cctype>
#include <unordered_set>

namespace picanha::ui {

// C keywords
static const std::unordered_set<std::string> C_KEYWORDS = {
    "if", "else", "while", "for", "do", "switch", "case", "default",
    "break", "continue", "return", "goto", "sizeof", "typedef",
    "struct", "union", "enum", "const", "volatile", "static", "extern",
    "register", "auto", "inline", "restrict", "_Bool", "_Complex"
};

// C types
static const std::unordered_set<std::string> C_TYPES = {
    "void", "char", "short", "int", "long", "float", "double",
    "signed", "unsigned", "bool", "int8_t", "int16_t", "int32_t", "int64_t",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t", "size_t", "ptrdiff_t",
    "intptr_t", "uintptr_t"
};

DecompiledView::DecompiledView(Application* app)
    : app_(app)
{
}

DecompiledView::~DecompiledView() = default;

void DecompiledView::render() {
    // Toolbar
    if (ImGui::Button("Refresh")) {
        refresh();
    }

    ImGui::SameLine();
    ImGui::Checkbox("Line #", &config_.show_line_numbers);

    ImGui::SameLine();
    if (!current_name_.empty()) {
        ImGui::Text("Function: %s", current_name_.c_str());
    }

    ImGui::Separator();

    // Status messages
    if (is_decompiling_) {
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Decompiling...");
        return;
    }

    if (!error_message_.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Error: %s", error_message_.c_str());
        return;
    }

    if (decompiled_code_.empty()) {
        ImGui::TextDisabled("No decompiled code available");
        ImGui::TextDisabled("Select a function and press 'D' to decompile");
        return;
    }

    // Content
    render_code();
}

void DecompiledView::set_function(std::shared_ptr<::picanha::lift::LiftedFunction> func) {
    if (func == current_function_) return;

    current_function_ = func;
    lines_dirty_ = true;
    error_message_.clear();

    if (func) {
        current_name_ = func->name();
        decompile_current();
    } else {
        current_name_.clear();
        decompiled_code_.clear();
        lines_.clear();
    }
}

void DecompiledView::clear() {
    current_function_.reset();
    current_name_.clear();
    decompiled_code_.clear();
    lines_.clear();
    error_message_.clear();
    lines_dirty_ = true;
}

void DecompiledView::refresh() {
    if (current_function_) {
        decompile_current();
    }
}

void DecompiledView::decompile_current() {
    if (!current_function_) return;

#ifdef PICANHA_ENABLE_DECOMPILER
    // Check if decompilation service is available
    if (!lift::DecompilationService::is_available()) {
        error_message_ = "Decompiler not available";
        return;
    }

    is_decompiling_ = true;
    error_message_.clear();

    // Get lifting service from app
    auto* lifting_service = app_->lifting_service();
    if (!lifting_service) {
        error_message_ = "Lifting service not available";
        is_decompiling_ = false;
        return;
    }

    // Create decompilation service
    auto* context = lifting_service->context();
    if (!context) {
        error_message_ = "Lifting context not available";
        is_decompiling_ = false;
        return;
    }

    lift::DecompilationService decompiler(context);
    lift::DecompilationConfig config;
    config.lower_switches = true;  // Usually better for readability

    auto result = decompiler.decompile_function_copy(*current_function_, config);

    is_decompiling_ = false;

    if (result.success) {
        decompiled_code_ = std::move(result.code);
        lines_dirty_ = true;
        scroll_to_top_ = true;

        if (decompiled_code_.empty()) {
            decompiled_code_ = "// Function decompiled but produced no output";
        }
    } else {
        error_message_ = result.error_message;
        decompiled_code_.clear();
        lines_.clear();
    }
#else
    error_message_ = "Decompiler not built (PICANHA_ENABLE_DECOMPILER is OFF)";
    decompiled_code_.clear();
    lines_.clear();
#endif
}

void DecompiledView::render_code() {
    // Parse lines if needed
    if (lines_dirty_) {
        lines_.clear();
        std::istringstream stream(decompiled_code_);
        std::string line;
        while (std::getline(stream, line)) {
            lines_.push_back(line);
        }
        lines_dirty_ = false;
    }

    // Scrolling content
    ImGuiWindowFlags flags = ImGuiWindowFlags_HorizontalScrollbar;
    if (ImGui::BeginChild("DecompiledContent", ImVec2(0, 0), ImGuiChildFlags_None, flags)) {
        float line_height = ImGui::GetTextLineHeightWithSpacing();

        // Handle scroll to top
        if (scroll_to_top_) {
            ImGui::SetScrollY(0);
            scroll_to_top_ = false;
        }

        // Virtualized rendering
        float scroll_y = ImGui::GetScrollY();
        float window_height = ImGui::GetWindowHeight();

        int first_visible = static_cast<int>(scroll_y / line_height);
        int visible_count = static_cast<int>(window_height / line_height) + 2;

        first_visible = std::clamp(first_visible, 0, std::max(0, static_cast<int>(lines_.size()) - 1));
        int last_visible = std::min(first_visible + visible_count, static_cast<int>(lines_.size()));

        // Set cursor to first visible line
        ImGui::SetCursorPosY(first_visible * line_height);

        for (int i = first_visible; i < last_visible; ++i) {
            render_line(lines_[i], static_cast<std::size_t>(i));
        }

        // Add dummy space for scrolling
        float total_height = lines_.size() * line_height;
        ImGui::SetCursorPosY(total_height);
    }
    ImGui::EndChild();
}

void DecompiledView::render_line(const std::string& line, std::size_t line_num) {
    // Line number
    if (config_.show_line_numbers) {
        ImGui::TextColored(ImColor(config_.color_comment).Value, "%4zu ", line_num + 1);
        ImGui::SameLine(0, 0);
    }

    // Parse and render tokens with syntax highlighting
    std::string token;
    bool in_string = false;
    bool in_comment = false;
    bool in_line_comment = false;

    for (std::size_t i = 0; i < line.size(); ++i) {
        char c = line[i];

        // Handle comments
        if (!in_string && !in_comment && i + 1 < line.size()) {
            if (c == '/' && line[i + 1] == '/') {
                // Render any pending token
                if (!token.empty()) {
                    render_token(token);
                    token.clear();
                }
                // Render rest of line as comment
                ImGui::TextColored(ImColor(config_.color_comment).Value, "%s", line.substr(i).c_str());
                ImGui::SameLine(0, 0);
                break;
            }
            if (c == '/' && line[i + 1] == '*') {
                in_comment = true;
            }
        }

        if (in_comment) {
            token += c;
            if (i > 0 && line[i - 1] == '*' && c == '/') {
                ImGui::TextColored(ImColor(config_.color_comment).Value, "%s", token.c_str());
                ImGui::SameLine(0, 0);
                token.clear();
                in_comment = false;
            }
            continue;
        }

        // Handle strings
        if (c == '"' && (i == 0 || line[i - 1] != '\\')) {
            if (in_string) {
                token += c;
                ImGui::TextColored(ImColor(config_.color_string).Value, "%s", token.c_str());
                ImGui::SameLine(0, 0);
                token.clear();
                in_string = false;
            } else {
                if (!token.empty()) {
                    render_token(token);
                    token.clear();
                }
                in_string = true;
                token += c;
            }
            continue;
        }

        if (in_string) {
            token += c;
            continue;
        }

        // Handle token boundaries
        if (std::isalnum(c) || c == '_') {
            token += c;
        } else {
            if (!token.empty()) {
                render_token(token);
                token.clear();
            }
            // Render the separator character
            if (!std::isspace(c)) {
                ImGui::TextColored(ImColor(config_.color_operator).Value, "%c", c);
                ImGui::SameLine(0, 0);
            } else {
                ImGui::Text("%c", c);
                ImGui::SameLine(0, 0);
            }
        }
    }

    // Render any remaining token
    if (!token.empty()) {
        if (in_string || in_comment) {
            ImU32 color = in_string ? config_.color_string : config_.color_comment;
            ImGui::TextColored(ImColor(color).Value, "%s", token.c_str());
        } else {
            render_token(token);
        }
        ImGui::SameLine(0, 0);
    }

    // New line
    ImGui::NewLine();
}

void DecompiledView::render_token(const std::string& token) {
    ImU32 color = config_.color_default;

    if (is_keyword(token)) {
        color = config_.color_keyword;
    } else if (is_type(token)) {
        color = config_.color_type;
    } else if (!token.empty() && std::isdigit(token[0])) {
        color = config_.color_number;
    } else if (token.size() > 1 && token[0] == '0' && (token[1] == 'x' || token[1] == 'X')) {
        color = config_.color_number;
    }

    ImGui::TextColored(ImColor(color).Value, "%s", token.c_str());
    ImGui::SameLine(0, 0);
}

bool DecompiledView::is_keyword(const std::string& token) const {
    return C_KEYWORDS.count(token) > 0;
}

bool DecompiledView::is_type(const std::string& token) const {
    return C_TYPES.count(token) > 0;
}

const std::string& DecompiledView::current_function_name() const {
    return current_name_;
}

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
