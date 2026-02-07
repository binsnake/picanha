#pragma once

#include <picanha/core/types.hpp>
#include <picanha/analysis/function.hpp>

#include <QWidget>
#include <QTreeView>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QLineEdit>

namespace picanha::ui {

class MainWindow;

// Function list widget with filtering and sorting
class FunctionListWidget : public QWidget {
    Q_OBJECT

public:
    explicit FunctionListWidget(MainWindow* window, QWidget* parent = nullptr);
    ~FunctionListWidget() override;

    // Selection
    void selectFunction(FunctionId id);
    [[nodiscard]] FunctionId selectedFunction() const;

    // Refresh from data
    void refresh();

signals:
    void functionSelected(FunctionId id);
    void functionDoubleClicked(FunctionId id);

private slots:
    void onSelectionChanged();
    void onDoubleClicked(const QModelIndex& index);
    void onFilterChanged(const QString& text);

private:
    void setupUI();
    void populateModel();

    MainWindow* window_;

    QLineEdit* filter_edit_;
    QTreeView* tree_view_;
    QStandardItemModel* model_;
    QSortFilterProxyModel* proxy_model_;
};

} // namespace picanha::ui
