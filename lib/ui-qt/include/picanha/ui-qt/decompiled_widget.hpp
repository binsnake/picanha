#pragma once

#ifdef PICANHA_ENABLE_LLVM

#include <picanha/core/types.hpp>
#include <picanha/lift/lifted_function.hpp>

#include <QWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QFuture>
#include <QFutureWatcher>

#include <memory>

namespace picanha::ui {

class MainWindow;
class CHighlighter;

// Decompiled C code viewer
class DecompiledWidget : public QWidget {
    Q_OBJECT

public:
    explicit DecompiledWidget(MainWindow* window, QWidget* parent = nullptr);
    ~DecompiledWidget() override;

    // Set the lifted function
    void setLiftedFunction(std::shared_ptr<lift::LiftedFunction> lifted);

    // Refresh
    void refresh();

private slots:
    void onDecompile();
    void onDecompilationFinished();

private:
    void setupUI();
    void updateDisplay();

    MainWindow* window_;
    QPushButton* decompile_button_;
    QLabel* status_label_;
    QPlainTextEdit* text_edit_;
    CHighlighter* highlighter_;

    std::shared_ptr<lift::LiftedFunction> lifted_;
    QString decompiled_code_;

    QFuture<QString> decompile_future_;
    QFutureWatcher<QString>* decompile_watcher_;
    bool decompiling_{false};
};

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
