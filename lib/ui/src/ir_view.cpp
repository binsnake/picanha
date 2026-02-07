#ifdef PICANHA_ENABLE_LLVM

#include <picanha/ui/ir_view.hpp>
#include <picanha/ui/app.hpp>

#include <algorithm>
#include <sstream>
#include <unordered_set>

namespace picanha::ui {

// Alias for cleaner code
namespace plift = ::picanha::lift;

namespace {

// LLVM IR keywords
const std::unordered_set<std::string> keywords = {
    "define", "declare", "ret", "br", "switch", "indirectbr",
    "invoke", "resume", "unreachable", "call", "tail", "musttail",
    "add", "sub", "mul", "udiv", "sdiv", "urem", "srem",
    "and", "or", "xor", "shl", "lshr", "ashr",
    "fadd", "fsub", "fmul", "fdiv", "frem",
    "icmp", "fcmp", "eq", "ne", "ugt", "uge", "ult", "ule",
    "sgt", "sge", "slt", "sle", "oeq", "one", "ogt", "oge", "olt", "ole",
    "trunc", "zext", "sext", "fptrunc", "fpext",
    "fptoui", "fptosi", "uitofp", "sitofp",
    "ptrtoint", "inttoptr", "bitcast", "addrspacecast",
    "alloca", "load", "store", "getelementptr", "extractvalue", "insertvalue",
    "phi", "select", "fence", "cmpxchg", "atomicrmw",
    "to", "label", "nuw", "nsw", "exact", "inbounds",
    "volatile", "atomic", "unordered", "monotonic", "acquire", "release",
    "acq_rel", "seq_cst", "singlethread",
    "null", "undef", "poison", "zeroinitializer", "true", "false",
    "private", "internal", "available_externally", "linkonce", "weak",
    "common", "appending", "extern_weak", "linkonce_odr", "weak_odr", "external",
    "default", "hidden", "protected",
    "dllimport", "dllexport",
    "ccc", "fastcc", "coldcc", "webkit_jscc", "anyregcc", "preserve_mostcc",
    "preserve_allcc", "cxx_fast_tlscc", "swiftcc", "tailcc",
    "nounwind", "readnone", "readonly", "writeonly", "argmemonly",
    "returns_twice", "noreturn", "noinline", "alwaysinline",
    "optnone", "optsize", "minsize", "uwtable", "naked",
    "align", "dereferenceable", "dereferenceable_or_null",
    "inreg", "byval", "inalloca", "sret", "noalias", "nocapture",
    "nest", "returned", "nonnull", "swifterror", "swiftself",
    "source_filename", "target", "datalayout", "triple",
    "global", "constant", "attributes", "metadata", "type"
};

// LLVM IR types
const std::unordered_set<std::string> types = {
    "void", "i1", "i8", "i16", "i32", "i64", "i128",
    "half", "bfloat", "float", "double", "fp128", "x86_fp80", "ppc_fp128",
    "ptr", "x86_amx", "x86_mmx", "token", "label", "metadata"
};

} // anonymous namespace

IRView::IRView(Application* app)
    : app_(app)
{
}

IRView::~IRView() = default;

void IRView::set_function(std::shared_ptr<plift::LiftedFunction> func) {
    current_function_ = std::move(func);
    lines_dirty_ = true;
    scroll_to_top_ = true;
}

void IRView::clear() {
    current_function_.reset();
    lines_.clear();
    lines_dirty_ = false;
}

const std::string& IRView::current_function_name() const {
    static const std::string empty;
    if (!current_function_) return empty;
    return current_function_->name();
}

void IRView::render() {
    if (!current_function_) {
        ImGui::TextDisabled("No function lifted. Select a function and press 'L' to lift.");
        return;
    }

    // Status
    ImGui::Text("Function: %s", current_function_->name().c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("(%s)", plift::to_string(current_function_->status()));
    ImGui::Separator();

    // Render the IR
    render_ir_text();
}

void IRView::render_ir_text() {
    // Parse lines if dirty
    if (lines_dirty_) {
        lines_.clear();
        const std::string& ir = current_function_->ir_text();

        std::istringstream stream(ir);
        std::string line;
        while (std::getline(stream, line)) {
            lines_.push_back(std::move(line));
        }
        lines_dirty_ = false;
    }

    // Scrolling region
    ImGuiWindowFlags window_flags = ImGuiWindowFlags_HorizontalScrollbar;
    ImGui::BeginChild("IRText", ImVec2(0, 0), false, window_flags);

    if (scroll_to_top_) {
        ImGui::SetScrollY(0);
        scroll_to_top_ = false;
    }

    // Use clipper for large content
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(lines_.size()));

    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
            render_line(lines_[i], static_cast<std::size_t>(i));
        }
    }

    clipper.End();
    ImGui::EndChild();
}

void IRView::render_line(const std::string& line, std::size_t line_num) {
    // Line number
    if (config_.show_line_numbers) {
        ImGui::TextColored(ImColor(config_.color_comment).Value, "%4zu ", line_num + 1);
        ImGui::SameLine(0, 0);
    }

    // Empty line
    if (line.empty()) {
        ImGui::TextUnformatted("");
        return;
    }

    // Simple tokenization and coloring
    std::string current_token;
    bool in_string = false;
    bool in_comment = false;

    for (std::size_t i = 0; i < line.size(); ++i) {
        char c = line[i];

        // Handle comments
        if (c == ';' && !in_string) {
            // Flush current token
            if (!current_token.empty()) {
                render_token(current_token);
                current_token.clear();
            }
            // Render rest of line as comment
            ImGui::SameLine(0, 0);
            ImGui::TextColored(ImColor(config_.color_comment).Value, "%s",
                               line.substr(i).c_str());
            break;
        }

        // Handle strings
        if (c == '"' && (i == 0 || line[i-1] != '\\')) {
            if (!in_string) {
                // Start of string - flush token
                if (!current_token.empty()) {
                    render_token(current_token);
                    current_token.clear();
                }
                in_string = true;
                current_token += c;
            } else {
                // End of string
                current_token += c;
                ImGui::SameLine(0, 0);
                ImGui::TextColored(ImColor(config_.color_string).Value, "%s",
                                   current_token.c_str());
                current_token.clear();
                in_string = false;
            }
            continue;
        }

        if (in_string) {
            current_token += c;
            continue;
        }

        // Token separators
        if (c == ' ' || c == '\t' || c == ',' || c == '(' || c == ')' ||
            c == '[' || c == ']' || c == '{' || c == '}' || c == ':' ||
            c == '=' || c == '*' || c == '@' || c == '%' || c == '!' ||
            c == '#' || c == '<' || c == '>') {

            // Flush current token
            if (!current_token.empty()) {
                render_token(current_token);
                current_token.clear();
            }

            // Render the separator
            ImGui::SameLine(0, 0);

            // Special coloring for some separators
            if (c == '@' || c == '%') {
                // Start of global or register
                current_token += c;
            } else {
                char sep[2] = {c, '\0'};
                ImGui::TextColored(ImColor(config_.color_default).Value, "%s", sep);
            }
        } else {
            current_token += c;
        }
    }

    // Flush remaining token
    if (!current_token.empty()) {
        render_token(current_token);
    }

    // Force newline
    ImGui::NewLine();
}

void IRView::render_token(const std::string& token) {
    if (token.empty()) return;

    ImGui::SameLine(0, 0);

    ImU32 color = config_.color_default;

    // Check token type
    if (token[0] == '%') {
        // Register/local variable
        color = config_.color_register;
    } else if (token[0] == '@') {
        // Global/function reference
        color = config_.color_label;
    } else if (is_keyword(token)) {
        color = config_.color_keyword;
    } else if (is_type(token)) {
        color = config_.color_type;
    } else if (!token.empty() && (std::isdigit(token[0]) || token[0] == '-')) {
        // Number
        color = config_.color_number;
    }

    ImGui::TextColored(ImColor(color).Value, "%s", token.c_str());
}

bool IRView::is_keyword(const std::string& token) const {
    return keywords.find(token) != keywords.end();
}

bool IRView::is_type(const std::string& token) const {
    return types.find(token) != types.end();
}

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
