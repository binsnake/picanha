#pragma once

#ifdef PICANHA_ENABLE_LLVM

#include <picanha/lift/lifted_function.hpp>
#include <picanha/lift/types.hpp>
#include <imgui.h>
#include <future>
#include <memory>
#include <string>
#include <vector>

namespace picanha::ui {

class Application;

// View for displaying optimized IR with optimization controls
class OptimizedView {
public:
    explicit OptimizedView(Application* app);
    ~OptimizedView();

    // Render the view
    void render();

    // Set the function to display
    void set_function(std::shared_ptr<::picanha::lift::LiftedFunction> func);
    void clear();

    // Optimization level
    [[nodiscard]] ::picanha::lift::OptimizationLevel optimization_level() const noexcept {
        return opt_level_;
    }
    void set_optimization_level(::picanha::lift::OptimizationLevel level);

    // Status
    [[nodiscard]] bool has_content() const { return current_function_ != nullptr; }
    [[nodiscard]] bool is_optimizing() const { return optimizing_; }

private:
    void render_controls();
    void render_ir_content();
    void trigger_optimization();
    void check_optimization_complete();

    Application* app_;
    std::shared_ptr<::picanha::lift::LiftedFunction> current_function_;
    ::picanha::lift::OptimizationLevel opt_level_{::picanha::lift::OptimizationLevel::O2};

    // Optimization state
    bool optimizing_{false};
    std::future<bool> opt_future_;

    // Parsed lines for rendering
    std::vector<std::string> lines_;
    bool lines_dirty_{true};

    // Scroll state
    float scroll_y_{0.0f};
    bool scroll_to_top_{false};
};

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
