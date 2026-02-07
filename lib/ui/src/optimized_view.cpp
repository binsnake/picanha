#ifdef PICANHA_ENABLE_LLVM

#include <picanha/ui/optimized_view.hpp>
#include <picanha/ui/app.hpp>
#include <picanha/lift/lifting_service.hpp>

#include <sstream>

namespace picanha::ui {

// Alias for cleaner code
namespace plift = ::picanha::lift;

OptimizedView::OptimizedView(Application* app)
    : app_(app)
{
}

OptimizedView::~OptimizedView() = default;

void OptimizedView::set_function(std::shared_ptr<plift::LiftedFunction> func) {
    current_function_ = std::move(func);
    lines_dirty_ = true;
    scroll_to_top_ = true;

    // If already optimized at current level, use cached IR
    if (current_function_ && current_function_->has_optimized_ir(opt_level_)) {
        lines_dirty_ = true;
    }
}

void OptimizedView::clear() {
    current_function_.reset();
    lines_.clear();
    lines_dirty_ = false;
    optimizing_ = false;
}

void OptimizedView::set_optimization_level(plift::OptimizationLevel level) {
    if (level == opt_level_) return;

    opt_level_ = level;
    lines_dirty_ = true;

    // Trigger optimization if we have a function and don't have this level cached
    if (current_function_ && !current_function_->has_optimized_ir(level)) {
        trigger_optimization();
    }
}

void OptimizedView::render() {
    // Check if async optimization completed
    check_optimization_complete();

    render_controls();
    ImGui::Separator();
    render_ir_content();
}

void OptimizedView::render_controls() {
    // Optimization level selector
    ImGui::Text("Optimization Level:");
    ImGui::SameLine();

    const char* levels[] = { "O0 (None)", "O1 (Basic)", "O2 (Standard)", "O3 (Aggressive)" };
    int current = static_cast<int>(opt_level_);

    ImGui::SetNextItemWidth(150);
    if (ImGui::Combo("##OptLevel", &current, levels, 4)) {
        set_optimization_level(static_cast<plift::OptimizationLevel>(current));
    }

    // Optimize button
    ImGui::SameLine();
    bool can_optimize = current_function_ && !optimizing_ &&
                       current_function_->status() == plift::LiftStatus::Lifted;

    if (!can_optimize) ImGui::BeginDisabled();
    if (ImGui::Button("Optimize")) {
        trigger_optimization();
    }
    if (!can_optimize) ImGui::EndDisabled();

    // Status
    ImGui::SameLine();
    if (optimizing_) {
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 0.0f, 1.0f), "Optimizing...");
    } else if (current_function_) {
        if (current_function_->has_optimized_ir(opt_level_)) {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Ready");
        } else {
            ImGui::TextDisabled("Not optimized");
        }
    }
}

void OptimizedView::render_ir_content() {
    if (!current_function_) {
        ImGui::TextDisabled("No function selected.");
        return;
    }

    if (optimizing_) {
        ImGui::TextDisabled("Optimization in progress...");
        return;
    }

    // Get the appropriate IR text
    const std::string* ir_text = nullptr;
    if (opt_level_ == plift::OptimizationLevel::O0) {
        ir_text = &current_function_->ir_text();
    } else if (current_function_->has_optimized_ir(opt_level_)) {
        ir_text = &current_function_->optimized_ir_text(opt_level_);
    }

    if (!ir_text || ir_text->empty()) {
        ImGui::TextDisabled("No optimized IR available. Click 'Optimize' to generate.");
        return;
    }

    // Parse lines if dirty
    if (lines_dirty_) {
        lines_.clear();
        std::istringstream stream(*ir_text);
        std::string line;
        while (std::getline(stream, line)) {
            lines_.push_back(std::move(line));
        }
        lines_dirty_ = false;
    }

    // Scrolling region
    ImGuiWindowFlags window_flags = ImGuiWindowFlags_HorizontalScrollbar;
    ImGui::BeginChild("OptimizedIRText", ImVec2(0, 0), false, window_flags);

    if (scroll_to_top_) {
        ImGui::SetScrollY(0);
        scroll_to_top_ = false;
    }

    // Use clipper for large content
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(lines_.size()));

    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
            // Line number
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "%4d ", i + 1);
            ImGui::SameLine(0, 0);
            ImGui::TextUnformatted(lines_[i].c_str());
        }
    }

    clipper.End();
    ImGui::EndChild();
}

void OptimizedView::trigger_optimization() {
    if (!current_function_ || optimizing_) return;

    auto* service = app_->lifting_service();
    if (!service) return;

    optimizing_ = true;
    opt_future_ = service->optimize_async(current_function_, opt_level_);
}

void OptimizedView::check_optimization_complete() {
    if (!optimizing_) return;

    // Check if future is ready
    if (opt_future_.valid() &&
        opt_future_.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {

        bool success = opt_future_.get();
        optimizing_ = false;
        lines_dirty_ = true;

        if (success) {
            app_->log("Optimization complete at level " +
                      std::string(plift::to_string(opt_level_)));
        } else {
            app_->log_error("Optimization failed");
        }
    }
}

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
