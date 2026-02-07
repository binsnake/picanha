#ifdef PICANHA_ENABLE_LLVM

#include <picanha/ui-qt/ir_widget.hpp>
#include <picanha/ui-qt/main_window.hpp>
#include <picanha/ui-qt/syntax_highlighter.hpp>

#include <QVBoxLayout>
#include <QFontDatabase>

namespace picanha::ui {

IRWidget::IRWidget(MainWindow* window, QWidget* parent)
    : QWidget(parent)
    , window_(window)
    , text_edit_(new QPlainTextEdit(this))
{
    setupUI();
}

IRWidget::~IRWidget() = default;

void IRWidget::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);

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
    )");
}

void IRWidget::setLiftedFunction(std::shared_ptr<lift::LiftedFunction> lifted) {
    lifted_ = std::move(lifted);
    updateDisplay();
}

void IRWidget::refresh() {
    updateDisplay();
}

void IRWidget::updateDisplay() {
    if (!lifted_) {
        text_edit_->setPlainText(tr("No function lifted"));
        return;
    }

    QString ir = QString::fromStdString(lifted_->ir_text());
    if (ir.isEmpty()) {
        text_edit_->setPlainText(tr("No IR available"));
    } else {
        text_edit_->setPlainText(ir);
    }
}

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
