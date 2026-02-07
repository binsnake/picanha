#pragma once

#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>
#include <picanha/analysis/function.hpp>
#include <picanha/analysis/symbol_table.hpp>
#include <picanha/analysis/xref_manager.hpp>
#include <picanha/persistence/project.hpp>
#include <imgui.h>
#include <atomic>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <functional>
#include <optional>

struct GLFWwindow;

#ifdef PICANHA_ENABLE_LLVM
namespace picanha::lift {
class LiftingService;
class LiftedFunction;
} // namespace picanha::lift
#endif

namespace picanha::ui {

// Forward declarations
class View;
class DisasmView;
class HexView;
class FunctionList;
class SymbolList;
class XRefList;
class ImportsView;

#ifdef PICANHA_ENABLE_LLVM
class IRView;
class OptimizedView;
class DecompiledView;
#endif

// Application configuration
struct AppConfig {
    std::string title{"Picanha Disassembler"};
    int window_width{1600};
    int window_height{900};
    bool vsync{true};
    float font_size{14.0f};
    std::string font_path;  // Empty = use default
    bool dark_theme{true};
};

// Navigation history entry
struct NavEntry {
    Address address;
    std::string description;
};

// Application state
struct AppState {
    // Current selection
    Address current_address{INVALID_ADDRESS};
    FunctionId current_function{INVALID_FUNCTION_ID};
    std::optional<BlockId> current_block;

    // Navigation
    std::vector<NavEntry> nav_history;
    std::size_t nav_position{0};

    // UI state
    bool show_hex_view{true};
    bool show_function_list{true};
    bool show_symbol_list{true};
    bool show_imports{true};
    bool show_xref_list{true};
    bool show_output_log{true};
    bool show_demo_window{false};

    // Analysis state
    bool analysis_running{false};
    float analysis_progress{0.0f};
    std::string analysis_status;

#ifdef PICANHA_ENABLE_LLVM
    // Lifting state
    bool show_ir_view{false};
    bool show_optimized_view{false};
    bool show_decompiled_view{false};
#endif
};

// Main application class
class Application {
public:
    explicit Application(const AppConfig& config = {});
    ~Application();

    // Non-copyable
    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;

    // Initialization
    [[nodiscard]] bool initialize();
    void shutdown();

    // Main loop
    void run();
    [[nodiscard]] bool should_close() const;
    void request_close();

    // Project management
    [[nodiscard]] bool new_project(const std::string& path, const std::string& name);
    [[nodiscard]] bool open_project(const std::string& path);
    [[nodiscard]] bool save_project();
    [[nodiscard]] bool close_project();
    [[nodiscard]] bool has_project() const { return project_ != nullptr; }

    // Binary loading
    [[nodiscard]] bool load_binary(const std::string& path);
    [[nodiscard]] bool has_binary() const { return binary_ != nullptr; }

    // Navigation
    void navigate_to(Address address);
    void navigate_to_function(FunctionId id);
    void navigate_back();
    void navigate_forward();
    [[nodiscard]] bool can_navigate_back() const;
    [[nodiscard]] bool can_navigate_forward() const;

    // Selection
    void select_address(Address addr);
    void select_function(FunctionId id);

    // Access to data
    [[nodiscard]] std::shared_ptr<loader::Binary> binary() const { return binary_; }
    [[nodiscard]] persistence::Project* project() const { return project_.get(); }
    [[nodiscard]] const std::vector<analysis::Function>& functions() const { return functions_; }
    [[nodiscard]] analysis::SymbolTable& symbols() { return symbols_; }
    [[nodiscard]] analysis::XRefManager& xrefs() { return xrefs_; }
    [[nodiscard]] AppState& state() { return state_; }

    // Analysis
    void run_analysis();
    void stop_analysis();

    // Logging
    void log(const std::string& message);
    void log_warning(const std::string& message);
    void log_error(const std::string& message);

    // Get window handle
    [[nodiscard]] GLFWwindow* window() const { return window_; }

#ifdef PICANHA_ENABLE_LLVM
    // Lifting
    void lift_current_function();
    void lift_function(FunctionId id);
    [[nodiscard]] ::picanha::lift::LiftingService* lifting_service() { return lifting_service_.get(); }
    [[nodiscard]] const ::picanha::lift::LiftingService* lifting_service() const { return lifting_service_.get(); }
    [[nodiscard]] bool has_lifting_service() const { return lifting_service_ != nullptr; }
    [[nodiscard]] std::shared_ptr<::picanha::lift::LiftedFunction> current_lifted() const { return current_lifted_; }

    // Decompilation
    void decompile_current_function();
#endif

private:
    // Frame rendering
    void begin_frame();
    void end_frame();
    void render_ui();

    // Main UI components
    void render_main_menu();
    void render_toolbar();
    void render_status_bar();
    void render_dockspace(float toolbar_height, float status_height);

    // Dialogs
    void show_open_binary_dialog();
    void show_new_project_dialog();
    void show_open_project_dialog();
    void show_about_dialog();
    void show_settings_dialog();
    void show_goto_address_dialog();

    // Keyboard shortcuts (processed via ImGui input system)
    void process_shortcuts();

    // Background analysis
    void run_analysis_background();
    void check_analysis_completion();

    // Theme setup
    void setup_theme();
    void setup_fonts();

    // Callbacks
    static void glfw_error_callback(int error, const char* description);
    static void glfw_key_callback(GLFWwindow* window, int key, int scancode, int action, int mods);
    static void glfw_drop_callback(GLFWwindow* window, int count, const char** paths);

    AppConfig config_;
    GLFWwindow* window_{nullptr};

    // Data
    std::shared_ptr<loader::Binary> binary_;
    std::unique_ptr<persistence::Project> project_;
    std::vector<analysis::Function> functions_;
    analysis::SymbolTable symbols_;
    analysis::XRefManager xrefs_;

    // Views
    std::unique_ptr<DisasmView> disasm_view_;
    std::unique_ptr<HexView> hex_view_;
    std::unique_ptr<FunctionList> function_list_;
    std::unique_ptr<SymbolList> symbol_list_;
    std::unique_ptr<ImportsView> imports_view_;
    std::unique_ptr<XRefList> xref_list_;

#ifdef PICANHA_ENABLE_LLVM
    // Lifting
    std::unique_ptr<::picanha::lift::LiftingService> lifting_service_;
    std::unique_ptr<IRView> ir_view_;
    std::unique_ptr<OptimizedView> optimized_view_;
    std::unique_ptr<DecompiledView> decompiled_view_;
    std::shared_ptr<::picanha::lift::LiftedFunction> current_lifted_;
#endif

    // State
    AppState state_;

    // Log buffer
    std::vector<std::string> log_buffer_;
    std::size_t max_log_entries_{1000};

    // Dialog state
    bool show_open_binary_{false};
    bool show_new_project_{false};
    bool show_open_project_{false};
    bool show_about_{false};
    bool show_settings_{false};
    bool show_goto_address_{false};
    std::string dialog_path_;
    std::string dialog_name_;
    char goto_address_buf_[32]{};

    // DPI scaling
    float dpi_scale_{1.0f};

    // Background analysis
    struct AnalysisResults {
        std::vector<analysis::Function> functions;
        analysis::SymbolTable symbols;
        analysis::XRefManager xrefs;
        std::vector<std::string> logs;
    };
    std::future<void> analysis_future_;
    std::atomic<float> analysis_progress_atomic_{0.0f};
    std::atomic<bool> analysis_complete_{false};
    std::mutex analysis_mutex_;
    std::unique_ptr<AnalysisResults> pending_results_;
};

// Singleton access (optional, for convenience)
Application* get_app();
void set_app(Application* app);

} // namespace picanha::ui
