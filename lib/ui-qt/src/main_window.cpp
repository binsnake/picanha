#include <picanha/ui-qt/main_window.hpp>
#include <picanha/ui-qt/disasm_widget.hpp>
#include <picanha/ui-qt/hex_widget.hpp>
#include <picanha/ui-qt/function_list_widget.hpp>
#include <picanha/ui-qt/symbol_list_widget.hpp>
#include <picanha/ui-qt/xref_list_widget.hpp>
#include <picanha/ui-qt/imports_widget.hpp>
#include <picanha/ui-qt/log_widget.hpp>

#ifdef PICANHA_ENABLE_LLVM
#include <picanha/ui-qt/ir_widget.hpp>
#include <picanha/ui-qt/optimized_widget.hpp>
#include <picanha/ui-qt/decompiled_widget.hpp>
#include <picanha/lift/lifting_service.hpp>
#endif

#include <picanha/loader/binary.hpp>
#include <picanha/analysis/function_detector.hpp>
#include <picanha/analysis/symbol.hpp>
#include <picanha/disasm/disassembly_context.hpp>

#include <QApplication>
#include <QMenuBar>
#include <QMenu>
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QSettings>
#include <QCloseEvent>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <QShortcut>
#include <QtConcurrent>

namespace picanha::ui {

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , analysis_watcher_(new QFutureWatcher<void>(this))
    , progress_timer_(new QTimer(this))
{
    setWindowTitle("Picanha Disassembler");
    setMinimumSize(1200, 800);
    resize(1600, 900);
    setAcceptDrops(true);

    setupUI();
    setupMenus();
    setupToolbar();
    setupDocks();
    setupStatusBar();
    setupShortcuts();
    restoreLayout();

    connect(analysis_watcher_, &QFutureWatcher<void>::finished,
            this, &MainWindow::onAnalysisFinished);
    connect(progress_timer_, &QTimer::timeout,
            this, &MainWindow::updateAnalysisProgress);
}

MainWindow::~MainWindow() {
    saveLayout();
    if (analysis_running_) {
        analysis_running_ = false;
        analysis_future_.waitForFinished();
    }
}

void MainWindow::setupUI() {
    // Main window styling
    setStyleSheet(R"(
        QMainWindow {
            background-color: #1e1e1e;
        }
        QDockWidget {
            color: #d4d4d4;
            titlebar-close-icon: url(:/icons/close.png);
        }
        QDockWidget::title {
            background-color: #2d2d2d;
            padding: 6px;
            text-align: left;
        }
        QToolBar {
            background-color: #2d2d2d;
            border: none;
            spacing: 3px;
        }
        QStatusBar {
            background-color: #007acc;
            color: white;
        }
        QMenuBar {
            background-color: #2d2d2d;
            color: #d4d4d4;
        }
        QMenuBar::item:selected {
            background-color: #3d3d3d;
        }
        QMenu {
            background-color: #2d2d2d;
            color: #d4d4d4;
            border: 1px solid #3d3d3d;
        }
        QMenu::item:selected {
            background-color: #094771;
        }
    )");
}

void MainWindow::setupMenus() {
    // File menu
    auto* fileMenu = menuBar()->addMenu(tr("&File"));

    auto* newProjectAction = fileMenu->addAction(tr("&New Project..."));
    newProjectAction->setShortcut(QKeySequence::New);
    connect(newProjectAction, &QAction::triggered, this, &MainWindow::onNewProject);

    auto* openProjectAction = fileMenu->addAction(tr("&Open Project..."));
    openProjectAction->setShortcut(QKeySequence::Open);
    connect(openProjectAction, &QAction::triggered, this, &MainWindow::onOpenProject);

    auto* saveProjectAction = fileMenu->addAction(tr("&Save Project"));
    saveProjectAction->setShortcut(QKeySequence::Save);
    connect(saveProjectAction, &QAction::triggered, this, &MainWindow::onSaveProject);

    auto* closeProjectAction = fileMenu->addAction(tr("&Close Project"));
    connect(closeProjectAction, &QAction::triggered, this, &MainWindow::onCloseProject);

    fileMenu->addSeparator();

    auto* openBinaryAction = fileMenu->addAction(tr("Open &Binary..."));
    openBinaryAction->setShortcut(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_O));
    connect(openBinaryAction, &QAction::triggered, this, &MainWindow::onOpenBinary);

    fileMenu->addSeparator();

    auto* exitAction = fileMenu->addAction(tr("E&xit"));
    exitAction->setShortcut(QKeySequence::Quit);
    connect(exitAction, &QAction::triggered, this, &MainWindow::onExit);

    // Edit menu
    auto* editMenu = menuBar()->addMenu(tr("&Edit"));

    auto* gotoAction = editMenu->addAction(tr("&Go to Address..."));
    gotoAction->setShortcut(QKeySequence(Qt::Key_G));
    connect(gotoAction, &QAction::triggered, this, &MainWindow::onGotoAddress);

    auto* findAction = editMenu->addAction(tr("&Find..."));
    findAction->setShortcut(QKeySequence::Find);
    connect(findAction, &QAction::triggered, this, &MainWindow::onFind);

    auto* findNextAction = editMenu->addAction(tr("Find &Next"));
    findNextAction->setShortcut(QKeySequence::FindNext);
    connect(findNextAction, &QAction::triggered, this, &MainWindow::onFindNext);

    // View menu
    auto* viewMenu = menuBar()->addMenu(tr("&View"));

    auto* viewDisasmAction = viewMenu->addAction(tr("&Disassembly"));
    viewDisasmAction->setCheckable(true);
    viewDisasmAction->setChecked(true);
    connect(viewDisasmAction, &QAction::triggered, this, &MainWindow::onViewDisassembly);

    auto* viewHexAction = viewMenu->addAction(tr("&Hex View"));
    viewHexAction->setCheckable(true);
    viewHexAction->setChecked(true);
    connect(viewHexAction, &QAction::triggered, this, &MainWindow::onViewHex);

    auto* viewFunctionsAction = viewMenu->addAction(tr("&Functions"));
    viewFunctionsAction->setCheckable(true);
    viewFunctionsAction->setChecked(true);
    connect(viewFunctionsAction, &QAction::triggered, this, &MainWindow::onViewFunctions);

    auto* viewSymbolsAction = viewMenu->addAction(tr("&Symbols"));
    viewSymbolsAction->setCheckable(true);
    viewSymbolsAction->setChecked(true);
    connect(viewSymbolsAction, &QAction::triggered, this, &MainWindow::onViewSymbols);

    auto* viewImportsAction = viewMenu->addAction(tr("&Imports"));
    viewImportsAction->setCheckable(true);
    viewImportsAction->setChecked(true);
    connect(viewImportsAction, &QAction::triggered, this, &MainWindow::onViewImports);

    auto* viewXRefsAction = viewMenu->addAction(tr("Cross-&References"));
    viewXRefsAction->setCheckable(true);
    viewXRefsAction->setChecked(true);
    connect(viewXRefsAction, &QAction::triggered, this, &MainWindow::onViewXRefs);

    auto* viewLogAction = viewMenu->addAction(tr("&Log"));
    viewLogAction->setCheckable(true);
    viewLogAction->setChecked(true);
    connect(viewLogAction, &QAction::triggered, this, &MainWindow::onViewLog);

#ifdef PICANHA_ENABLE_LLVM
    viewMenu->addSeparator();

    auto* viewIRAction = viewMenu->addAction(tr("&IR View"));
    viewIRAction->setCheckable(true);
    viewIRAction->setShortcut(QKeySequence(Qt::Key_I));
    connect(viewIRAction, &QAction::triggered, this, &MainWindow::onViewIR);

    auto* viewOptimizedAction = viewMenu->addAction(tr("&Optimized IR"));
    viewOptimizedAction->setCheckable(true);
    connect(viewOptimizedAction, &QAction::triggered, this, &MainWindow::onViewOptimized);

    auto* viewDecompiledAction = viewMenu->addAction(tr("D&ecompiled"));
    viewDecompiledAction->setCheckable(true);
    viewDecompiledAction->setShortcut(QKeySequence(Qt::Key_D));
    connect(viewDecompiledAction, &QAction::triggered, this, &MainWindow::onViewDecompiled);
#endif

    // Analysis menu
    auto* analysisMenu = menuBar()->addMenu(tr("&Analysis"));

    auto* runAnalysisAction = analysisMenu->addAction(tr("&Run Analysis"));
    runAnalysisAction->setShortcut(QKeySequence(Qt::Key_F5));
    connect(runAnalysisAction, &QAction::triggered, this, &MainWindow::onRunAnalysis);

    auto* stopAnalysisAction = analysisMenu->addAction(tr("&Stop Analysis"));
    stopAnalysisAction->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F5));
    connect(stopAnalysisAction, &QAction::triggered, this, &MainWindow::onStopAnalysis);

#ifdef PICANHA_ENABLE_LLVM
    analysisMenu->addSeparator();

    auto* liftAction = analysisMenu->addAction(tr("&Lift Function"));
    liftAction->setShortcut(QKeySequence(Qt::Key_L));
    connect(liftAction, &QAction::triggered, this, &MainWindow::onLiftFunction);

    auto* decompileAction = analysisMenu->addAction(tr("&Decompile Function"));
    decompileAction->setShortcut(QKeySequence(Qt::Key_F5));
    connect(decompileAction, &QAction::triggered, this, &MainWindow::onDecompileFunction);
#endif

    // Help menu
    auto* helpMenu = menuBar()->addMenu(tr("&Help"));

    auto* aboutAction = helpMenu->addAction(tr("&About..."));
    connect(aboutAction, &QAction::triggered, this, &MainWindow::onAbout);

    auto* settingsAction = helpMenu->addAction(tr("&Settings..."));
    connect(settingsAction, &QAction::triggered, this, &MainWindow::onSettings);
}

void MainWindow::setupToolbar() {
    main_toolbar_ = addToolBar(tr("Main"));
    main_toolbar_->setMovable(false);
    main_toolbar_->setIconSize(QSize(16, 16));

    action_back_ = main_toolbar_->addAction(QIcon(":/icons/back.png"), tr("Back"));
    action_back_->setShortcut(QKeySequence(Qt::ALT | Qt::Key_Left));
    action_back_->setEnabled(false);
    connect(action_back_, &QAction::triggered, this, &MainWindow::navigateBack);

    action_forward_ = main_toolbar_->addAction(QIcon(":/icons/forward.png"), tr("Forward"));
    action_forward_->setShortcut(QKeySequence(Qt::ALT | Qt::Key_Right));
    action_forward_->setEnabled(false);
    connect(action_forward_, &QAction::triggered, this, &MainWindow::navigateForward);

    main_toolbar_->addSeparator();

    action_run_analysis_ = main_toolbar_->addAction(QIcon(":/icons/run.png"), tr("Run Analysis (F5)"));
    connect(action_run_analysis_, &QAction::triggered, this, &MainWindow::onRunAnalysis);

    action_stop_analysis_ = main_toolbar_->addAction(QIcon(":/icons/stop.png"), tr("Stop Analysis"));
    action_stop_analysis_->setEnabled(false);
    connect(action_stop_analysis_, &QAction::triggered, this, &MainWindow::onStopAnalysis);
}

void MainWindow::setupDocks() {
    setDockNestingEnabled(true);

    // Create widgets
    disasm_widget_ = new DisasmWidget(this, this);
    hex_widget_ = new HexWidget(this, this);
    function_list_ = new FunctionListWidget(this, this);
    symbol_list_ = new SymbolListWidget(this, this);
    xref_list_ = new XRefListWidget(this, this);
    imports_widget_ = new ImportsWidget(this, this);
    log_widget_ = new LogWidget(this);

    // Create docks (disasm_widget_ is central widget, not a dock)
    hex_dock_ = new QDockWidget(tr("Hex View"), this);
    hex_dock_->setWidget(hex_widget_);
    hex_dock_->setObjectName("HexDock");

    functions_dock_ = new QDockWidget(tr("Functions"), this);
    functions_dock_->setWidget(function_list_);
    functions_dock_->setObjectName("FunctionsDock");

    symbols_dock_ = new QDockWidget(tr("Symbols"), this);
    symbols_dock_->setWidget(symbol_list_);
    symbols_dock_->setObjectName("SymbolsDock");

    xrefs_dock_ = new QDockWidget(tr("Cross-References"), this);
    xrefs_dock_->setWidget(xref_list_);
    xrefs_dock_->setObjectName("XRefsDock");

    imports_dock_ = new QDockWidget(tr("Imports"), this);
    imports_dock_->setWidget(imports_widget_);
    imports_dock_->setObjectName("ImportsDock");

    log_dock_ = new QDockWidget(tr("Output"), this);
    log_dock_->setWidget(log_widget_);
    log_dock_->setObjectName("LogDock");

    // Add docks to main window
    addDockWidget(Qt::LeftDockWidgetArea, functions_dock_);
    addDockWidget(Qt::LeftDockWidgetArea, imports_dock_);
    tabifyDockWidget(functions_dock_, imports_dock_);
    functions_dock_->raise();

    setCentralWidget(disasm_widget_);

    addDockWidget(Qt::RightDockWidgetArea, symbols_dock_);
    addDockWidget(Qt::RightDockWidgetArea, xrefs_dock_);
    tabifyDockWidget(symbols_dock_, xrefs_dock_);
    symbols_dock_->raise();

    addDockWidget(Qt::BottomDockWidgetArea, hex_dock_);
    addDockWidget(Qt::BottomDockWidgetArea, log_dock_);
    tabifyDockWidget(hex_dock_, log_dock_);
    hex_dock_->raise();

#ifdef PICANHA_ENABLE_LLVM
    ir_widget_ = new IRWidget(this, this);
    optimized_widget_ = new OptimizedWidget(this, this);
    decompiled_widget_ = new DecompiledWidget(this, this);

    ir_dock_ = new QDockWidget(tr("LLVM IR"), this);
    ir_dock_->setWidget(ir_widget_);
    ir_dock_->setObjectName("IRDock");
    ir_dock_->hide();

    optimized_dock_ = new QDockWidget(tr("Optimized IR"), this);
    optimized_dock_->setWidget(optimized_widget_);
    optimized_dock_->setObjectName("OptimizedDock");
    optimized_dock_->hide();

    decompiled_dock_ = new QDockWidget(tr("Decompiled"), this);
    decompiled_dock_->setWidget(decompiled_widget_);
    decompiled_dock_->setObjectName("DecompiledDock");
    decompiled_dock_->hide();

    addDockWidget(Qt::RightDockWidgetArea, ir_dock_);
    addDockWidget(Qt::RightDockWidgetArea, optimized_dock_);
    addDockWidget(Qt::RightDockWidgetArea, decompiled_dock_);
#endif

    // Connect selection signals
    connect(function_list_, &FunctionListWidget::functionSelected,
            this, &MainWindow::navigateToFunction);
    connect(symbol_list_, &SymbolListWidget::symbolSelected,
            this, &MainWindow::navigateTo);
    connect(imports_widget_, &ImportsWidget::importSelected,
            this, &MainWindow::navigateTo);
    connect(xref_list_, &XRefListWidget::xrefSelected,
            this, &MainWindow::navigateTo);
}

void MainWindow::setupStatusBar() {
    status_label_ = new QLabel(tr("Ready"));
    address_label_ = new QLabel();
    progress_bar_ = new QProgressBar();
    progress_bar_->setMaximumWidth(200);
    progress_bar_->setMaximum(100);
    progress_bar_->hide();

    statusBar()->addWidget(status_label_, 1);
    statusBar()->addPermanentWidget(address_label_);
    statusBar()->addPermanentWidget(progress_bar_);
}

void MainWindow::setupShortcuts() {
    // Additional shortcuts
    new QShortcut(QKeySequence(Qt::Key_Escape), this, [this]() {
        // Cancel current operation
        if (analysis_running_) {
            stopAnalysis();
        }
    });
}

void MainWindow::restoreLayout() {
    QSettings settings("Picanha", "Disassembler");
    restoreGeometry(settings.value("geometry").toByteArray());
    restoreState(settings.value("windowState").toByteArray());
    last_open_path_ = settings.value("lastOpenPath").toString();
    last_project_path_ = settings.value("lastProjectPath").toString();
}

void MainWindow::saveLayout() {
    QSettings settings("Picanha", "Disassembler");
    settings.setValue("geometry", saveGeometry());
    settings.setValue("windowState", saveState());
    settings.setValue("lastOpenPath", last_open_path_);
    settings.setValue("lastProjectPath", last_project_path_);
}

// Project management

bool MainWindow::newProject(const QString& path, const QString& name) {
    if (hasProject()) {
        closeProject();
    }

    project_ = std::make_unique<persistence::Project>();
    if (!project_->create(path.toStdString(), name.toStdString())) {
        project_.reset();
        return false;
    }

    setWindowTitle(QString("Picanha - %1").arg(name));
    return true;
}

bool MainWindow::openProject(const QString& path) {
    if (hasProject()) {
        closeProject();
    }

    project_ = std::make_unique<persistence::Project>();
    auto result = project_->open(path.toStdString());
    if (!result.has_value()) {
        project_.reset();
        return false;
    }

    setWindowTitle(QString("Picanha - %1").arg(QString::fromStdString(project_->info().name)));
    return true;
}

bool MainWindow::saveProject() {
    if (!hasProject()) {
        return false;
    }
    return project_->save().has_value();
}

bool MainWindow::closeProject() {
    if (!hasProject()) {
        return true;
    }

    project_.reset();
    binary_.reset();
    functions_.clear();
    symbols_.clear();
    xrefs_.clear();

    setWindowTitle("Picanha Disassembler");
    return true;
}

// Binary loading

bool MainWindow::loadBinary(const QString& path) {
    log(QString("Loading binary: %1").arg(path));

    try {
        auto result = loader::Binary::load_file(path.toStdString());
        if (!result.has_value()) {
            auto msg = result.error().message();
            logError(QString("Failed to load binary: %1").arg(QString::fromUtf8(msg.data(), static_cast<qsizetype>(msg.size()))));
            return false;
        }

        // Convert unique_ptr to shared_ptr
        binary_ = std::shared_ptr<loader::Binary>(std::move(result.value()));

        log(QString("Loaded: %1").arg(QString::fromStdString(binary_->name())));
        log(QString("  Image base: 0x%1").arg(binary_->image_base(), 16, 16, QChar('0')));
        log(QString("  Entry point: 0x%1").arg(binary_->entry_point(), 16, 16, QChar('0')));
        log(QString("  Sections: %1").arg(binary_->sections().size()));

        last_open_path_ = QFileInfo(path).absolutePath();

        // Initialize lifting service if LLVM enabled
#ifdef PICANHA_ENABLE_LLVM
        // Temporarily disabled - may be causing crashes
        log("Skipping lifting service initialization...");
        // lifting_service_ = std::make_unique<::picanha::lift::LiftingService>(binary_);
        // if (!lifting_service_->initialize()) {
        //     logWarning("Failed to initialize lifting service");
        //     lifting_service_.reset();
        // }
#endif

        emit binaryLoaded();

        // Refresh widgets with error handling
        try {
            log("Refreshing disassembly widget...");
            disasm_widget_->refresh();
        } catch (const std::exception& e) {
            logError(QString("Disasm widget refresh failed: %1").arg(e.what()));
        }

        try {
            log("Refreshing hex widget...");
            hex_widget_->refresh();
        } catch (const std::exception& e) {
            logError(QString("Hex widget refresh failed: %1").arg(e.what()));
        }

        try {
            log("Refreshing function list...");
            function_list_->refresh();
        } catch (const std::exception& e) {
            logError(QString("Function list refresh failed: %1").arg(e.what()));
        }

        try {
            log("Refreshing imports widget...");
            imports_widget_->refresh();
        } catch (const std::exception& e) {
            logError(QString("Imports widget refresh failed: %1").arg(e.what()));
        }

        // Navigate to entry point
        try {
            log("Navigating to entry point...");
            navigateTo(binary_->entry_point());
        } catch (const std::exception& e) {
            logError(QString("Navigation failed: %1").arg(e.what()));
        }

        return true;
    } catch (const std::exception& e) {
        logError(QString("Exception loading binary: %1").arg(e.what()));
        return false;
    }
}

// Navigation

void MainWindow::navigateTo(Address address) {
    if (address == INVALID_ADDRESS) return;

    // Add to navigation history
    if (current_address_ != INVALID_ADDRESS) {
        if (nav_position_ < nav_history_.size()) {
            nav_history_.resize(nav_position_);
        }
        nav_history_.push_back({current_address_, QString("0x%1").arg(current_address_, 16, 16, QChar('0'))});
        nav_position_ = nav_history_.size();
    }

    current_address_ = address;
    address_label_->setText(QString("Address: 0x%1").arg(address, 16, 16, QChar('0')));

    // Update navigation buttons
    action_back_->setEnabled(canNavigateBack());
    action_forward_->setEnabled(canNavigateForward());

    // Update views
    disasm_widget_->gotoAddress(address);
    hex_widget_->gotoAddress(address);

    emit addressSelected(address);
}

void MainWindow::navigateToFunction(FunctionId id) {
    if (id == INVALID_FUNCTION_ID) return;

    for (const auto& func : functions_) {
        if (func.id() == id) {
            current_function_ = id;
            navigateTo(func.entry_address());
            emit functionSelected(id);
            return;
        }
    }
}

void MainWindow::navigateBack() {
    if (!canNavigateBack()) return;

    nav_position_--;
    current_address_ = nav_history_[nav_position_].address;

    address_label_->setText(QString("Address: 0x%1").arg(current_address_, 16, 16, QChar('0')));
    action_back_->setEnabled(canNavigateBack());
    action_forward_->setEnabled(canNavigateForward());

    disasm_widget_->gotoAddress(current_address_);
    hex_widget_->gotoAddress(current_address_);

    emit addressSelected(current_address_);
}

void MainWindow::navigateForward() {
    if (!canNavigateForward()) return;

    nav_position_++;
    current_address_ = nav_history_[nav_position_].address;

    address_label_->setText(QString("Address: 0x%1").arg(current_address_, 16, 16, QChar('0')));
    action_back_->setEnabled(canNavigateBack());
    action_forward_->setEnabled(canNavigateForward());

    disasm_widget_->gotoAddress(current_address_);
    hex_widget_->gotoAddress(current_address_);

    emit addressSelected(current_address_);
}

bool MainWindow::canNavigateBack() const {
    return nav_position_ > 0;
}

bool MainWindow::canNavigateForward() const {
    return nav_position_ < nav_history_.size();
}

// Selection

void MainWindow::selectAddress(Address addr) {
    current_address_ = addr;
    emit addressSelected(addr);
}

void MainWindow::selectFunction(FunctionId id) {
    current_function_ = id;
    emit functionSelected(id);
}

// Analysis

void MainWindow::runAnalysis() {
    if (!hasBinary() || analysis_running_) {
        return;
    }

    log("Starting analysis...");
    status_label_->setText(tr("Analyzing..."));
    progress_bar_->setValue(0);
    progress_bar_->show();
    action_run_analysis_->setEnabled(false);
    action_stop_analysis_->setEnabled(true);

    analysis_running_ = true;
    analysis_progress_atomic_ = 0.0f;

    progress_timer_->start(100);

    analysis_future_ = QtConcurrent::run([this]() {
        runAnalysisBackground();
    });
    analysis_watcher_->setFuture(analysis_future_);

    emit analysisStarted();
}

void MainWindow::stopAnalysis() {
    if (!analysis_running_) return;

    log("Stopping analysis...");
    analysis_running_ = false;
}

void MainWindow::runAnalysisBackground() {
    auto results = std::make_unique<AnalysisResults>();

    try {
        // Create disassembly context
        auto context = std::make_shared<disasm::DisassemblyContext>(binary_);

        // Create function detector
        analysis::FunctionDetectorConfig config;
        config.use_exception_info = true;
        config.use_exports = true;
        config.use_imports = true;
        config.use_call_targets = true;
        config.build_cfg = true;

        analysis::FunctionDetector detector(binary_, context, config);

        // Progress callback
        std::atomic<std::size_t> total_funcs{0};
        detector.detect([this, &total_funcs](std::size_t current, std::size_t total, const char* /*phase*/) {
            total_funcs = total;
            if (total > 0) {
                analysis_progress_atomic_ = static_cast<float>(current) / static_cast<float>(total);
            }
        });

        // Get results
        results->functions = detector.take_functions();
        results->logs.append(QString("Found %1 functions").arg(results->functions.size()));

        // Build symbol table from functions
        for (const auto& func : results->functions) {
            analysis::Symbol sym;
            sym.name = func.name();
            sym.address = func.entry_address();
            sym.size = func.size();
            sym.type = analysis::SymbolType::Function;
            results->symbols.add(std::move(sym));
        }
    } catch (const std::exception& e) {
        results->logs.append(QString("Exception: %1").arg(e.what()));
    }

    std::lock_guard<std::mutex> lock(analysis_mutex_);
    pending_results_ = std::move(results);
    analysis_progress_atomic_ = 1.0f;
}

void MainWindow::updateAnalysisProgress() {
    float progress = analysis_progress_atomic_.load();
    progress_bar_->setValue(static_cast<int>(progress * 100));
    emit analysisProgress(progress, status_label_->text());
}

void MainWindow::onAnalysisFinished() {
    progress_timer_->stop();
    analysis_running_ = false;

    std::unique_ptr<AnalysisResults> results;
    {
        std::lock_guard<std::mutex> lock(analysis_mutex_);
        results = std::move(pending_results_);
    }

    if (results) {
        functions_ = std::move(results->functions);
        symbols_ = std::move(results->symbols);
        xrefs_ = std::move(results->xrefs);

        for (const auto& msg : results->logs) {
            log(msg);
        }
    }

    progress_bar_->hide();
    action_run_analysis_->setEnabled(true);
    action_stop_analysis_->setEnabled(false);
    status_label_->setText(tr("Analysis complete"));

    // Refresh views
    disasm_widget_->refresh();
    function_list_->refresh();
    symbol_list_->refresh();
    xref_list_->refresh();

    log(QString("Analysis complete: %1 functions").arg(functions_.size()));
    emit analysisCompleted();
}

// Logging

void MainWindow::log(const QString& message) {
    log_widget_->appendMessage(message);
}

void MainWindow::logWarning(const QString& message) {
    log_widget_->appendWarning(message);
}

void MainWindow::logError(const QString& message) {
    log_widget_->appendError(message);
}

// Event handlers

void MainWindow::closeEvent(QCloseEvent* event) {
    if (analysis_running_) {
        auto result = QMessageBox::question(this, tr("Analysis Running"),
            tr("Analysis is still running. Are you sure you want to exit?"),
            QMessageBox::Yes | QMessageBox::No);

        if (result == QMessageBox::No) {
            event->ignore();
            return;
        }

        analysis_running_ = false;
        analysis_future_.waitForFinished();
    }

    saveLayout();
    event->accept();
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event) {
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent* event) {
    const auto urls = event->mimeData()->urls();
    if (!urls.isEmpty()) {
        loadBinary(urls.first().toLocalFile());
    }
}

// Menu action slots

void MainWindow::onNewProject() {
    QString path = QFileDialog::getSaveFileName(this, tr("New Project"),
        last_project_path_, tr("Picanha Project (*.picanha)"));
    if (path.isEmpty()) return;

    QString name = QInputDialog::getText(this, tr("Project Name"),
        tr("Enter project name:"));
    if (name.isEmpty()) return;

    if (newProject(path, name)) {
        last_project_path_ = QFileInfo(path).absolutePath();
        log(QString("Created project: %1").arg(name));
    } else {
        QMessageBox::critical(this, tr("Error"), tr("Failed to create project"));
    }
}

void MainWindow::onOpenProject() {
    QString path = QFileDialog::getOpenFileName(this, tr("Open Project"),
        last_project_path_, tr("Picanha Project (*.picanha)"));
    if (path.isEmpty()) return;

    if (openProject(path)) {
        last_project_path_ = QFileInfo(path).absolutePath();
        log(QString("Opened project: %1").arg(path));
    } else {
        QMessageBox::critical(this, tr("Error"), tr("Failed to open project"));
    }
}

void MainWindow::onSaveProject() {
    if (saveProject()) {
        log("Project saved");
    } else {
        QMessageBox::critical(this, tr("Error"), tr("Failed to save project"));
    }
}

void MainWindow::onCloseProject() {
    closeProject();
    log("Project closed");
}

void MainWindow::onOpenBinary() {
    QString path = QFileDialog::getOpenFileName(this, tr("Open Binary"),
        last_open_path_, tr("Executable Files (*.exe *.dll *.sys);;All Files (*)"));
    if (path.isEmpty()) return;

    loadBinary(path);
}

void MainWindow::onExit() {
    close();
}

void MainWindow::onGotoAddress() {
    bool ok;
    QString text = QInputDialog::getText(this, tr("Go to Address"),
        tr("Enter address (hex):"), QLineEdit::Normal, QString(), &ok);

    if (ok && !text.isEmpty()) {
        bool converted;
        Address addr = text.toULongLong(&converted, 16);
        if (converted) {
            navigateTo(addr);
        } else {
            QMessageBox::warning(this, tr("Invalid Address"),
                tr("Could not parse address: %1").arg(text));
        }
    }
}

void MainWindow::onFind() {
    // TODO: Implement search dialog
}

void MainWindow::onFindNext() {
    // TODO: Implement find next
}

void MainWindow::onViewDisassembly() {
    // Disassembly is the central widget, always visible
}

void MainWindow::onViewHex() {
    hex_dock_->setVisible(!hex_dock_->isVisible());
}

void MainWindow::onViewFunctions() {
    functions_dock_->setVisible(!functions_dock_->isVisible());
}

void MainWindow::onViewSymbols() {
    symbols_dock_->setVisible(!symbols_dock_->isVisible());
}

void MainWindow::onViewImports() {
    imports_dock_->setVisible(!imports_dock_->isVisible());
}

void MainWindow::onViewXRefs() {
    xrefs_dock_->setVisible(!xrefs_dock_->isVisible());
}

void MainWindow::onViewLog() {
    log_dock_->setVisible(!log_dock_->isVisible());
}

void MainWindow::onRunAnalysis() {
    runAnalysis();
}

void MainWindow::onStopAnalysis() {
    stopAnalysis();
}

#ifdef PICANHA_ENABLE_LLVM
void MainWindow::onViewIR() {
    ir_dock_->setVisible(!ir_dock_->isVisible());
}

void MainWindow::onViewOptimized() {
    optimized_dock_->setVisible(!optimized_dock_->isVisible());
}

void MainWindow::onViewDecompiled() {
    decompiled_dock_->setVisible(!decompiled_dock_->isVisible());
}

void MainWindow::onLiftFunction() {
    liftCurrentFunction();
}

void MainWindow::onDecompileFunction() {
    decompileCurrentFunction();
}

void MainWindow::liftCurrentFunction() {
    if (!lifting_service_ || current_function_ == INVALID_FUNCTION_ID) {
        return;
    }

    liftFunction(current_function_);
}

void MainWindow::liftFunction(FunctionId id) {
    if (!lifting_service_) return;

    for (const auto& func : functions_) {
        if (func.id() == id) {
            log(QString("Lifting function: %1").arg(QString::fromStdString(func.name())));

            auto result = lifting_service_->lift_function(func);
            if (result.success && result.lifted) {
                current_lifted_ = result.lifted;
                ir_widget_->setLiftedFunction(current_lifted_);
                optimized_widget_->setLiftedFunction(current_lifted_);
                ir_dock_->show();
                emit functionLifted(id);
            } else {
                logError(QString("Failed to lift function: %1").arg(QString::fromStdString(result.error)));
            }
            return;
        }
    }
}

void MainWindow::decompileCurrentFunction() {
    if (!current_lifted_) {
        liftCurrentFunction();
    }

    if (current_lifted_) {
        log("Decompiling function...");
        // Pass the lifted function to the widget which handles decompilation
        decompiled_widget_->setLiftedFunction(current_lifted_);
        decompiled_dock_->show();
        emit functionDecompiled(current_function_);
    }
}
#endif

void MainWindow::onAbout() {
    QMessageBox::about(this, tr("About Picanha"),
        tr("<h3>Picanha Disassembler</h3>"
           "<p>Version 0.1.0</p>"
           "<p>An x86_64 disassembler for Windows PE/COFF binaries.</p>"
           "<p>Built with Qt, LLVM, and Remill.</p>"));
}

void MainWindow::onSettings() {
    // TODO: Implement settings dialog
}

} // namespace picanha::ui
