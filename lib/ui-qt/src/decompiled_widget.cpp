#ifdef PICANHA_ENABLE_LLVM

#include <picanha/ui-qt/decompiled_widget.hpp>
#include <picanha/ui-qt/main_window.hpp>
#include <picanha/ui-qt/syntax_highlighter.hpp>
#include <picanha/lift/lifting_service.hpp>
#include <picanha/lift/decompilation_service.hpp>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFontDatabase>
#include <QtConcurrent>

namespace picanha::ui {

DecompiledWidget::DecompiledWidget(MainWindow* window, QWidget* parent)
    : QWidget(parent)
    , window_(window)
    , decompile_button_(new QPushButton(tr("Decompile"), this))
    , status_label_(new QLabel(this))
    , text_edit_(new QPlainTextEdit(this))
    , decompile_watcher_(new QFutureWatcher<QString>(this))
{
    setupUI();

    connect(decompile_watcher_, &QFutureWatcher<QString>::finished,
            this, &DecompiledWidget::onDecompilationFinished);
}

DecompiledWidget::~DecompiledWidget() {
    if (decompiling_) {
        decompile_future_.waitForFinished();
    }
}

void DecompiledWidget::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(2);

    // Toolbar
    auto* toolbar = new QHBoxLayout();
    toolbar->addWidget(decompile_button_);
    toolbar->addWidget(status_label_);
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
    highlighter_ = new CHighlighter(text_edit_->document());

    // Styling
    setStyleSheet(R"(
        QPlainTextEdit {
            background-color: #1e1e1e;
            color: #d4d4d4;
            border: none;
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
        QLabel {
            color: #808080;
        }
    )");

    // Connections
    connect(decompile_button_, &QPushButton::clicked, this, &DecompiledWidget::onDecompile);
}

void DecompiledWidget::setLiftedFunction(std::shared_ptr<lift::LiftedFunction> lifted) {
    lifted_ = std::move(lifted);
    decompiled_code_.clear();
    updateDisplay();
}

void DecompiledWidget::refresh() {
    updateDisplay();
}

void DecompiledWidget::onDecompile() {
    if (!lifted_ || !window_->liftingService() || decompiling_) {
        return;
    }

    decompiling_ = true;
    decompile_button_->setEnabled(false);
    decompile_button_->setText(tr("Decompiling..."));
    status_label_->setText(tr("Running Rellic decompiler..."));

    auto* service = window_->liftingService();
    auto lifted = lifted_;

    decompile_future_ = QtConcurrent::run([service, lifted]() -> QString {
        // Check if decompilation is available
        if (!::picanha::lift::DecompilationService::is_available()) {
            return QString("// Decompilation not available (Rellic not built)");
        }

        // Create decompilation service and run decompilation
        ::picanha::lift::DecompilationService decompiler(service->context());
        auto result = decompiler.decompile_function_copy(*lifted);

        if (result.success) {
            return QString::fromStdString(result.code);
        } else {
            return QString("// Decompilation error:\n// %1").arg(QString::fromStdString(result.error_message));
        }
    });
    decompile_watcher_->setFuture(decompile_future_);
}

void DecompiledWidget::onDecompilationFinished() {
    decompiling_ = false;
    decompile_button_->setEnabled(true);
    decompile_button_->setText(tr("Decompile"));

    QString result = decompile_future_.result();
    if (!result.startsWith("// Decompilation error")) {
        decompiled_code_ = result;
        status_label_->setText(tr("Decompilation complete"));
        updateDisplay();
        window_->log(tr("Decompilation completed"));
    } else {
        status_label_->setText(tr("Decompilation failed"));
        window_->logError(tr("Decompilation failed"));
        text_edit_->setPlainText(result);
    }
}

void DecompiledWidget::updateDisplay() {
    if (!lifted_) {
        text_edit_->setPlainText(tr("// No function lifted"));
        status_label_->clear();
        return;
    }

    if (decompiled_code_.isEmpty()) {
        text_edit_->setPlainText(tr("// Not decompiled yet. Click 'Decompile' to run the decompiler."));
        status_label_->clear();
    } else {
        text_edit_->setPlainText(decompiled_code_);
        status_label_->setText(tr("Decompiled"));
    }
}

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
