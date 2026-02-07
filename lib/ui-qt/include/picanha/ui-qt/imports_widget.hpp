#pragma once

#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>

#include <QWidget>
#include <QTreeView>
#include <QStandardItemModel>
#include <QLineEdit>
#include <QSortFilterProxyModel>

namespace picanha::ui {

class MainWindow;

// Imports view widget - shows imported functions organized by module
class ImportsWidget : public QWidget {
    Q_OBJECT

public:
    explicit ImportsWidget(MainWindow* window, QWidget* parent = nullptr);
    ~ImportsWidget() override;

    // Refresh from data
    void refresh();

signals:
    void importSelected(Address address);

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
