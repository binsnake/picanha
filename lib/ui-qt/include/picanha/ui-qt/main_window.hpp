#pragma once

#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>
#include <picanha/analysis/function.hpp>
#include <picanha/analysis/symbol_table.hpp>
#include <picanha/analysis/xref_manager.hpp>
#include <picanha/persistence/project.hpp>

#include <QMainWindow>
#include <QDockWidget>
#include <QToolBar>
#include <QStatusBar>
#include <QProgressBar>
#include <QLabel>
#include <QTimer>
#include <QFuture>
#include <QFutureWatcher>

#include <atomic>
#include <memory>
#include <mutex>
#include <vector>
#include <optional>

#ifdef PICANHA_ENABLE_LLVM
namespace picanha::lift {
class LiftingService;
class LiftedFunction;
} // namespace picanha::lift
#endif

namespace picanha::ui {

// Forward declarations
class DisasmWidget;
class HexWidget;
class FunctionListWidget;
class SymbolListWidget;
class XRefListWidget;
class ImportsWidget;
class LogWidget;

#ifdef PICANHA_ENABLE_LLVM
class IRWidget;
class OptimizedWidget;
class DecompiledWidget;
#endif

// Navigation history entry
struct NavEntry {
    Address address;
    QString description;
};

// Main application window
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    // Project management
    [[nodiscard]] bool newProject(const QString& path, const QString& name);
    [[nodiscard]] bool openProject(const QString& path);
    [[nodiscard]] bool saveProject();
    [[nodiscard]] bool closeProject();
    [[nodiscard]] bool hasProject() const { return project_ != nullptr; }

    // Binary loading
    [[nodiscard]] bool loadBinary(const QString& path);
    [[nodiscard]] bool hasBinary() const { return binary_ != nullptr; }

    // Navigation
    void navigateTo(Address address);
    void navigateToFunction(FunctionId id);
    void navigateBack();
    void navigateForward();
    [[nodiscard]] bool canNavigateBack() const;
    [[nodiscard]] bool canNavigateForward() const;

    // Selection
    void selectAddress(Address addr);
    void selectFunction(FunctionId id);

    // Access to data
    [[nodiscard]] std::shared_ptr<loader::Binary> binary() const { return binary_; }
    [[nodiscard]] persistence::Project* project() const { return project_.get(); }
    [[nodiscard]] const std::vector<analysis::Function>& functions() const { return functions_; }
    [[nodiscard]] analysis::SymbolTable& symbols() { return symbols_; }
    [[nodiscard]] analysis::XRefManager& xrefs() { return xrefs_; }

    // Analysis
    void runAnalysis();
    void stopAnalysis();

    // Logging
    void log(const QString& message);
    void logWarning(const QString& message);
    void logError(const QString& message);

    // Current selection
    [[nodiscard]] Address currentAddress() const { return current_address_; }
    [[nodiscard]] FunctionId currentFunction() const { return current_function_; }

#ifdef PICANHA_ENABLE_LLVM
    // Lifting
    void liftCurrentFunction();
    void liftFunction(FunctionId id);
    [[nodiscard]] ::picanha::lift::LiftingService* liftingService() { return lifting_service_.get(); }
    [[nodiscard]] std::shared_ptr<::picanha::lift::LiftedFunction> currentLifted() const { return current_lifted_; }

    // Decompilation
    void decompileCurrentFunction();
#endif

signals:
    void binaryLoaded();
    void analysisStarted();
    void analysisProgress(float progress, const QString& status);
    void analysisCompleted();
    void addressSelected(Address address);
    void functionSelected(FunctionId id);

#ifdef PICANHA_ENABLE_LLVM
    void functionLifted(FunctionId id);
    void functionDecompiled(FunctionId id);
#endif

public slots:
    // Public slots callable from child widgets
    void onGotoAddress();

protected:
    void closeEvent(QCloseEvent* event) override;
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dropEvent(QDropEvent* event) override;

private slots:
    // File menu actions
    void onNewProject();
    void onOpenProject();
    void onSaveProject();
    void onCloseProject();
    void onOpenBinary();
    void onExit();

    // Edit menu actions
    void onFind();
    void onFindNext();

    // View menu actions
    void onViewDisassembly();
    void onViewHex();
    void onViewFunctions();
    void onViewSymbols();
    void onViewImports();
    void onViewXRefs();
    void onViewLog();

    // Analysis menu actions
    void onRunAnalysis();
    void onStopAnalysis();

#ifdef PICANHA_ENABLE_LLVM
    void onViewIR();
    void onViewOptimized();
    void onViewDecompiled();
    void onLiftFunction();
    void onDecompileFunction();
#endif

    // Help menu actions
    void onAbout();
    void onSettings();

    // Internal slots
    void onAnalysisFinished();
    void updateAnalysisProgress();

private:
    // Setup
    void setupUI();
    void setupMenus();
    void setupToolbar();
    void setupDocks();
    void setupStatusBar();
    void setupShortcuts();
    void restoreLayout();
    void saveLayout();

    // Analysis background processing
    struct AnalysisResults {
        std::vector<analysis::Function> functions;
        analysis::SymbolTable symbols;
        analysis::XRefManager xrefs;
        QStringList logs;
    };
    void runAnalysisBackground();

    // Data
    std::shared_ptr<loader::Binary> binary_;
    std::unique_ptr<persistence::Project> project_;
    std::vector<analysis::Function> functions_;
    analysis::SymbolTable symbols_;
    analysis::XRefManager xrefs_;

    // Current selection
    Address current_address_{INVALID_ADDRESS};
    FunctionId current_function_{INVALID_FUNCTION_ID};
    std::optional<BlockId> current_block_;

    // Navigation history
    std::vector<NavEntry> nav_history_;
    std::size_t nav_position_{0};

    // Widgets
    DisasmWidget* disasm_widget_{nullptr};
    HexWidget* hex_widget_{nullptr};
    FunctionListWidget* function_list_{nullptr};
    SymbolListWidget* symbol_list_{nullptr};
    XRefListWidget* xref_list_{nullptr};
    ImportsWidget* imports_widget_{nullptr};
    LogWidget* log_widget_{nullptr};

    // Docks (disasm_widget_ is the central widget, not a dock)
    QDockWidget* hex_dock_{nullptr};
    QDockWidget* functions_dock_{nullptr};
    QDockWidget* symbols_dock_{nullptr};
    QDockWidget* xrefs_dock_{nullptr};
    QDockWidget* imports_dock_{nullptr};
    QDockWidget* log_dock_{nullptr};

#ifdef PICANHA_ENABLE_LLVM
    // LLVM widgets
    std::unique_ptr<::picanha::lift::LiftingService> lifting_service_;
    IRWidget* ir_widget_{nullptr};
    OptimizedWidget* optimized_widget_{nullptr};
    DecompiledWidget* decompiled_widget_{nullptr};
    QDockWidget* ir_dock_{nullptr};
    QDockWidget* optimized_dock_{nullptr};
    QDockWidget* decompiled_dock_{nullptr};
    std::shared_ptr<::picanha::lift::LiftedFunction> current_lifted_;
#endif

    // Toolbar
    QToolBar* main_toolbar_{nullptr};
    QAction* action_back_{nullptr};
    QAction* action_forward_{nullptr};
    QAction* action_run_analysis_{nullptr};
    QAction* action_stop_analysis_{nullptr};

    // Status bar
    QLabel* status_label_{nullptr};
    QLabel* address_label_{nullptr};
    QProgressBar* progress_bar_{nullptr};

    // Analysis state
    QFuture<void> analysis_future_;
    QFutureWatcher<void>* analysis_watcher_{nullptr};
    QTimer* progress_timer_{nullptr};
    std::atomic<float> analysis_progress_atomic_{0.0f};
    std::atomic<bool> analysis_running_{false};
    std::mutex analysis_mutex_;
    std::unique_ptr<AnalysisResults> pending_results_;

    // Settings
    QString last_open_path_;
    QString last_project_path_;
};

} // namespace picanha::ui
