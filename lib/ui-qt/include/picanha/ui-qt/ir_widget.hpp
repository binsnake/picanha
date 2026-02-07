#pragma once

#ifdef PICANHA_ENABLE_LLVM

#include <picanha/core/types.hpp>
#include <picanha/lift/lifted_function.hpp>

#include <QWidget>
#include <QPlainTextEdit>
#include <QComboBox>

#include <memory>

namespace picanha::ui {

class MainWindow;
class IRHighlighter;

// LLVM IR viewer widget
class IRWidget : public QWidget {
    Q_OBJECT

public:
    explicit IRWidget(MainWindow* window, QWidget* parent = nullptr);
    ~IRWidget() override;

    // Set the lifted function to display
    void setLiftedFunction(std::shared_ptr<lift::LiftedFunction> lifted);

    // Refresh
    void refresh();

private:
    void setupUI();
    void updateDisplay();

    MainWindow* window_;
    QPlainTextEdit* text_edit_;
    IRHighlighter* highlighter_;
    std::shared_ptr<lift::LiftedFunction> lifted_;
};

} // namespace picanha::ui

#endif // PICANHA_ENABLE_LLVM
