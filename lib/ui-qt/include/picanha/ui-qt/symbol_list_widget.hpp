#pragma once

#include <picanha/core/types.hpp>
#include <picanha/analysis/symbol_table.hpp>

#include <QWidget>
#include <QTreeView>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QLineEdit>

namespace picanha::ui {

class MainWindow;

// Symbol list widget with filtering and sorting
class SymbolListWidget : public QWidget {
    Q_OBJECT

public:
    explicit SymbolListWidget(MainWindow* window, QWidget* parent = nullptr);
    ~SymbolListWidget() override;

    // Selection
    void selectSymbol(Address address);

    // Refresh from data
    void refresh();

signals:
    void symbolSelected(Address address);

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
