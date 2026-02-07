#include <picanha/ui-qt/log_widget.hpp>

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDateTime>
#include <QScrollBar>

namespace picanha::ui {

LogWidget::LogWidget(QWidget* parent)
    : QWidget(parent)
    , text_edit_(new QPlainTextEdit(this))
    , clear_button_(new QPushButton(tr("Clear"), this))
{
    setupUI();
}

LogWidget::~LogWidget() = default;

void LogWidget::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(2);

    // Toolbar
    auto* toolbar = new QHBoxLayout();
    toolbar->addStretch();
    toolbar->addWidget(clear_button_);
    layout->addLayout(toolbar);

    // Text edit
    text_edit_->setReadOnly(true);
    text_edit_->setMaximumBlockCount(10000);
    text_edit_->setLineWrapMode(QPlainTextEdit::NoWrap);
    layout->addWidget(text_edit_);

    // Styling
    setStyleSheet(R"(
        QPlainTextEdit {
            background-color: #1e1e1e;
            color: #d4d4d4;
            border: none;
            font-family: monospace;
            font-size: 10pt;
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
    )");

    connect(clear_button_, &QPushButton::clicked, this, &LogWidget::clear);
}

void LogWidget::appendMessage(const QString& message) {
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    text_edit_->appendHtml(QString("<span style='color:#808080'>[%1]</span> %2")
        .arg(timestamp, message.toHtmlEscaped()));

    // Auto-scroll to bottom
    text_edit_->verticalScrollBar()->setValue(text_edit_->verticalScrollBar()->maximum());
}

void LogWidget::appendWarning(const QString& message) {
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    text_edit_->appendHtml(QString("<span style='color:#808080'>[%1]</span> <span style='color:#dcdcaa'>WARNING:</span> %2")
        .arg(timestamp, message.toHtmlEscaped()));

    text_edit_->verticalScrollBar()->setValue(text_edit_->verticalScrollBar()->maximum());
}

void LogWidget::appendError(const QString& message) {
    QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    text_edit_->appendHtml(QString("<span style='color:#808080'>[%1]</span> <span style='color:#f14c4c'>ERROR:</span> %2")
        .arg(timestamp, message.toHtmlEscaped()));

    text_edit_->verticalScrollBar()->setValue(text_edit_->verticalScrollBar()->maximum());
}

void LogWidget::clear() {
    text_edit_->clear();
}

} // namespace picanha::ui
