#pragma once

#include <picanha/core/types.hpp>
#include <picanha/analysis/xref_manager.hpp>

#include <QWidget>
#include <QTreeView>
#include <QStandardItemModel>
#include <QComboBox>

namespace picanha::ui {

class MainWindow;

// XRef mode
enum class XRefMode {
    ToAddress,
    FromAddress,
    Both
};

// Cross-reference list widget
class XRefListWidget : public QWidget {
    Q_OBJECT

public:
    explicit XRefListWidget(MainWindow* window, QWidget* parent = nullptr);
    ~XRefListWidget() override;

    // Set the address to show xrefs for
    void setAddress(Address address);

    // Set mode
    void setMode(XRefMode mode);

    // Refresh
    void refresh();

signals:
    void xrefSelected(Address address);

private slots:
    void onSelectionChanged();
    void onDoubleClicked(const QModelIndex& index);
    void onModeChanged(int index);

private:
    void setupUI();
    void populateModel();

    MainWindow* window_;

    QComboBox* mode_combo_;
    QTreeView* tree_view_;
    QStandardItemModel* model_;

    Address current_address_{INVALID_ADDRESS};
    XRefMode mode_{XRefMode::ToAddress};
};

} // namespace picanha::ui
