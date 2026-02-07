#ifdef PICANHA_ENABLE_LLVM

#include <picanha/ui-qt/optimized_widget.hpp>
#include <picanha/ui-qt/main_window.hpp>
#include <picanha/ui-qt/syntax_highlighter.hpp>
#include <picanha/lift/lifting_service.hpp>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFontDatabase>
#include <QtConcurrent>

namespace picanha::ui {

OptimizedWidget::OptimizedWidget(MainWindow* window, QWidget* parent)
    : QWidget(parent)
    , window_(window)
    , level_combo_(new QComboBox(this))
    , optimize_button_(new QPushButton(tr("Optimize"), this))
    , text_edit_(new QPlainTextEdit(this))
    , optimize_watcher_(new QFutureWatcher<bool>(this))
{
    setupUI();

    connect(optimize_watcher_, &QFutureWatcher<bool>::finished,
            this, &OptimizedWidget::onOptimizationFinished);
}

OptimizedWidget::~OptimizedWidget() {
    if (optimizing_) {
        optimize_future_.waitForFinished();
    }
}

void OptimizedWidget::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(2);

    // Toolbar
    auto* toolbar = new QHBoxLayout();

    level_combo_->addItem("O1", static_cast<int>(lift::OptimizationLevel::O1));
    level_combo_->addItem("O2", static_cast<int>(lift::OptimizationLevel::O2));
    level_combo_->addItem("O3", static_cast<int>(lift::OptimizationLevel::O3));
    toolbar->addWidget(level_combo_);

    toolbar->addWidget(optimize_button_);
    toolbar->addStretch();

    layout->addLayout(toolbar);

    // Text edit
    text_edit_->setReadOnly(true);
    text_edit_->setLineWrapMode(QPlainTextEdit::NoWrap);

    QFont mono_font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono_font.setPointSize(10);
    text_edit_->setFont(mono_font);

    layout->addWidget(text_edit_);

    // Syntax highlighter
    highlighter_ = new IRHighlighter(text_edit_->document());

    // Styling
    setStyleSheet(R"(
        QPlainTextEdit {
            background-color: #1e1e1e;
            color: #d4d4d4;
            border: none;
        }
        QComboBox {
            background-color: #2d2d2d;
            color: #d4d4d4;
            border: 1px solid #3d3d3d;
            padding: 4px;
        }
        QComboBox::drop-down {
            border: none;
        }
        QComboBox QAbstractItemView {
            background-color: #2d2d2d;
            color: #d4d4d4;
            selection-background-color: #264f78;
        }
        QPushButton {
            background-color: #3d3d3d;
            color: #d4d4d4;
            border: none;
            padding: 4px 12px;
        }
        QPushButton:hover {
            background-color: #4d4d4d;
        }
        QPushButton:pressed {
            background-color: #2d2d2d;
        }
        QPushButton:disabled {
            background-color: #2d2d2d;
            color: #808080;
        }
    )");

    // Connections
    connect(level_combo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &OptimizedWidget::onLevelChanged);
    connect(optimize_button_, &QPushButton::clicked, this, &OptimizedWidget::onOptimize);
}

void OptimizedWidget::setLiftedFunction(std::shared_ptr<lift::LiftedFunction> lifted) {
    lifted_ = std::move(lifted);
    updateDisplay();
}

void OptimizedWidget::refresh() {
    updateDisplay();
}

void OptimizedWidget::onOptimize() {
    if (!lifted_ || !window_->liftingService() || optimizing_) {
        return;
    }

    optimizing_ = true;
    optimize_button_->setEnabled(false);
    optimize_button_->setText(tr("Optimizing..."));

    auto* service = window_->liftingService();
    auto level = current_level_;
    auto lifted = lifted_;

    optimize_future_ = QtConcurrent::run([service, lifted, level]() -> bool {
        return service->optimize(*lifted, level);
    });
    optimize_watcher_->setFuture(optimize_future_);
}

void OptimizedWidget::onOptimizationFinished() {
    optimizing_ = false;
    optimize_button_->setEnabled(true);
    optimize_button_->setText(tr("Optimize"));

    bool success = optimize_future_.result();
    if (success) {
        updateDisplay();
        window_->log(tr("Optimization completed"));
    } else {
        window_->logError(tr("Optimization failed"));
    }
}

void OptimizedWidget::onLevelChanged(int index) {
    current_level_ = static_cast<lift::OptimizationLevel>(level_combo_->itemData(index).toInt());
}

void OptimizedWidget::updateDisplay() {
    if (!lifted_) {
        text_edit_->setPlainText(tr("No function lifted"));
        return;
    }

    QString ir = QString::fromStdString(lifted_->optimized_ir_text(current_level_));
    if (ir.isEmpty()) {
        text_edit_->setPlainText(tr("Not optimized yet. Click 'Optimize' to run optimization passes."));
    } else {
        text_edit_->setPlainText(ir);
    }
}

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
