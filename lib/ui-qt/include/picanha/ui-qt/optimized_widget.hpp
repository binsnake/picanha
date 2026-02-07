#pragma once

#ifdef PICANHA_ENABLE_LLVM

#include <picanha/core/types.hpp>
#include <picanha/lift/lifted_function.hpp>
#include <picanha/lift/types.hpp>

#include <QWidget>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QFuture>
#include <QFutureWatcher>

#include <memory>

namespace picanha::ui {

class MainWindow;
class IRHighlighter;

// Optimized IR viewer with optimization level control
class OptimizedWidget : public QWidget {
    Q_OBJECT

public:
    explicit OptimizedWidget(MainWindow* window, QWidget* parent = nullptr);
    ~OptimizedWidget() override;

    // Set the lifted function
    void setLiftedFunction(std::shared_ptr<lift::LiftedFunction> lifted);

    // Refresh
    void refresh();

private slots:
    void onOptimize();
    void onOptimizationFinished();
    void onLevelChanged(int index);

private:
    void setupUI();
    void updateDisplay();

    MainWindow* window_;
    QComboBox* level_combo_;
    QPushButton* optimize_button_;
    QPlainTextEdit* text_edit_;
    IRHighlighter* highlighter_;

    std::shared_ptr<lift::LiftedFunction> lifted_;
    lift::OptimizationLevel current_level_{lift::OptimizationLevel::O1};

    QFuture<bool> optimize_future_;
    QFutureWatcher<bool>* optimize_watcher_;
    bool optimizing_{false};
};

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
