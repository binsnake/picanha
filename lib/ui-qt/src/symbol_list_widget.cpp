#include <picanha/ui-qt/symbol_list_widget.hpp>
#include <picanha/ui-qt/main_window.hpp>

#include <QVBoxLayout>
#include <QHeaderView>

namespace picanha::ui {

SymbolListWidget::SymbolListWidget(MainWindow* window, QWidget* parent)
    : QWidget(parent)
    , window_(window)
    , filter_edit_(new QLineEdit(this))
    , tree_view_(new QTreeView(this))
    , model_(new QStandardItemModel(this))
    , proxy_model_(new QSortFilterProxyModel(this))
{
    setupUI();
}

SymbolListWidget::~SymbolListWidget() = default;

void SymbolListWidget::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(2);

    // Filter
    filter_edit_->setPlaceholderText(tr("Filter symbols..."));
    filter_edit_->setClearButtonEnabled(true);
    layout->addWidget(filter_edit_);

    // Tree view
    proxy_model_->setSourceModel(model_);
    proxy_model_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_model_->setFilterKeyColumn(1);

    tree_view_->setModel(proxy_model_);
    tree_view_->setRootIsDecorated(false);
    tree_view_->setAlternatingRowColors(true);
    tree_view_->setSortingEnabled(true);
    tree_view_->setSelectionMode(QAbstractItemView::SingleSelection);
    tree_view_->setSelectionBehavior(QAbstractItemView::SelectRows);

    layout->addWidget(tree_view_);

    // Styling
    setStyleSheet(R"(
        QTreeView {
            background-color: #1e1e1e;
            color: #d4d4d4;
            border: none;
            font-family: monospace;
        }
        QTreeView::item:selected {
            background-color: #264f78;
        }
        QTreeView::item:hover {
            background-color: #2d2d2d;
        }
        QHeaderView::section {
            background-color: #2d2d2d;
            color: #d4d4d4;
            padding: 4px;
            border: none;
            border-right: 1px solid #3d3d3d;
        }
        QLineEdit {
            background-color: #2d2d2d;
            color: #d4d4d4;
            border: 1px solid #3d3d3d;
            padding: 4px;
        }
    )");

    // Set up model headers
    model_->setHorizontalHeaderLabels({tr("Address"), tr("Name"), tr("Type")});

    // Connections
    connect(filter_edit_, &QLineEdit::textChanged, this, &SymbolListWidget::onFilterChanged);
    connect(tree_view_->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &SymbolListWidget::onSelectionChanged);
    connect(tree_view_, &QTreeView::doubleClicked, this, &SymbolListWidget::onDoubleClicked);
}

void SymbolListWidget::selectSymbol(Address address) {
    for (int i = 0; i < model_->rowCount(); ++i) {
        auto idx = model_->index(i, 0);
        if (model_->data(idx, Qt::UserRole).toULongLong() == address) {
            auto proxy_idx = proxy_model_->mapFromSource(idx);
            tree_view_->setCurrentIndex(proxy_idx);
            tree_view_->scrollTo(proxy_idx);
            return;
        }
    }
}

void SymbolListWidget::refresh() {
    populateModel();
}

void SymbolListWidget::onSelectionChanged() {
    auto indices = tree_view_->selectionModel()->selectedRows();
    if (indices.isEmpty()) return;

    auto source_idx = proxy_model_->mapToSource(indices.first());
    Address addr = model_->data(model_->index(source_idx.row(), 0), Qt::UserRole).toULongLong();
    if (addr != INVALID_ADDRESS) {
        emit symbolSelected(addr);
    }
}

void SymbolListWidget::onDoubleClicked(const QModelIndex& index) {
    auto source_idx = proxy_model_->mapToSource(index);
    Address addr = model_->data(model_->index(source_idx.row(), 0), Qt::UserRole).toULongLong();
    if (addr != INVALID_ADDRESS) {
        emit symbolSelected(addr);
    }
}

void SymbolListWidget::onFilterChanged(const QString& text) {
    proxy_model_->setFilterWildcard(text);
}

void SymbolListWidget::populateModel() {
    model_->removeRows(0, model_->rowCount());

    if (!window_) return;

    const auto& symbols = window_->symbols();

    for (const auto* sym : symbols.get_all()) {
        QList<QStandardItem*> row;

        // Address
        auto* addr_item = new QStandardItem(QString("0x%1").arg(sym->address, 16, 16, QChar('0')));
        addr_item->setData(static_cast<qulonglong>(sym->address), Qt::UserRole);
        addr_item->setEditable(false);

        // Name
        auto* name_item = new QStandardItem(QString::fromStdString(sym->name));
        name_item->setEditable(false);

        // Type
        QString type_str;
        switch (sym->type) {
            case analysis::SymbolType::Function: type_str = "Function"; break;
            case analysis::SymbolType::Data: type_str = "Data"; break;
            case analysis::SymbolType::Import: type_str = "Import"; break;
            case analysis::SymbolType::Export: type_str = "Export"; break;
            case analysis::SymbolType::Label: type_str = "Label"; break;
            case analysis::SymbolType::String: type_str = "String"; break;
            default: type_str = "Unknown"; break;
        }
        auto* type_item = new QStandardItem(type_str);
        type_item->setEditable(false);

        row << addr_item << name_item << type_item;
        model_->appendRow(row);
    }

    tree_view_->resizeColumnToContents(0);
    tree_view_->resizeColumnToContents(2);
}

} // namespace picanha::ui
