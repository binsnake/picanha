#pragma once

#include <QWidget>
#include <QPlainTextEdit>
#include <QPushButton>

namespace picanha::ui {

// Log/output widget
class LogWidget : public QWidget {
    Q_OBJECT

public:
    explicit LogWidget(QWidget* parent = nullptr);
    ~LogWidget() override;

    // Append messages
    void appendMessage(const QString& message);
    void appendWarning(const QString& message);
    void appendError(const QString& message);

    // Clear
    void clear();

private:
    void setupUI();

    QPlainTextEdit* text_edit_;
    QPushButton* clear_button_;
};

} // namespace picanha::ui
