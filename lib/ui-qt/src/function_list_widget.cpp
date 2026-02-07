#include <picanha/ui-qt/function_list_widget.hpp>
#include <picanha/ui-qt/main_window.hpp>

#include <QVBoxLayout>
#include <QHeaderView>

namespace picanha::ui {

FunctionListWidget::FunctionListWidget(MainWindow* window, QWidget* parent)
    : QWidget(parent)
    , window_(window)
    , filter_edit_(new QLineEdit(this))
    , tree_view_(new QTreeView(this))
    , model_(new QStandardItemModel(this))
    , proxy_model_(new QSortFilterProxyModel(this))
{
    setupUI();
}

FunctionListWidget::~FunctionListWidget() = default;

void FunctionListWidget::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(2);

    // Filter
    filter_edit_->setPlaceholderText(tr("Filter functions..."));
    filter_edit_->setClearButtonEnabled(true);
    layout->addWidget(filter_edit_);

    // Tree view
    proxy_model_->setSourceModel(model_);
    proxy_model_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_model_->setFilterKeyColumn(1);  // Filter by name

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
    model_->setHorizontalHeaderLabels({tr("Address"), tr("Name"), tr("Size"), tr("Type")});

    // Connections
    connect(filter_edit_, &QLineEdit::textChanged, this, &FunctionListWidget::onFilterChanged);
    connect(tree_view_->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &FunctionListWidget::onSelectionChanged);
    connect(tree_view_, &QTreeView::doubleClicked, this, &FunctionListWidget::onDoubleClicked);
}

void FunctionListWidget::selectFunction(FunctionId id) {
    for (int i = 0; i < model_->rowCount(); ++i) {
        auto idx = model_->index(i, 0);
        if (model_->data(idx, Qt::UserRole).toULongLong() == id) {
            auto proxy_idx = proxy_model_->mapFromSource(idx);
            tree_view_->setCurrentIndex(proxy_idx);
            tree_view_->scrollTo(proxy_idx);
            return;
        }
    }
}

FunctionId FunctionListWidget::selectedFunction() const {
    auto indices = tree_view_->selectionModel()->selectedRows();
    if (indices.isEmpty()) return INVALID_FUNCTION_ID;

    auto source_idx = proxy_model_->mapToSource(indices.first());
    return model_->data(source_idx, Qt::UserRole).toULongLong();
}

void FunctionListWidget::refresh() {
    populateModel();
}

void FunctionListWidget::onSelectionChanged() {
    auto id = selectedFunction();
    if (id != INVALID_FUNCTION_ID) {
        emit functionSelected(id);
    }
}

void FunctionListWidget::onDoubleClicked(const QModelIndex& index) {
    auto source_idx = proxy_model_->mapToSource(index);
    auto id = model_->data(model_->index(source_idx.row(), 0), Qt::UserRole).toULongLong();
    if (id != INVALID_FUNCTION_ID) {
        emit functionDoubleClicked(id);
    }
}

void FunctionListWidget::onFilterChanged(const QString& text) {
    proxy_model_->setFilterWildcard(text);
}

void FunctionListWidget::populateModel() {
    model_->removeRows(0, model_->rowCount());

    if (!window_) return;

    const auto& functions = window_->functions();

    for (const auto& func : functions) {
        QList<QStandardItem*> row;

        // Address
        auto* addr_item = new QStandardItem(QString("0x%1").arg(func.entry_address(), 16, 16, QChar('0')));
        addr_item->setData(static_cast<qulonglong>(func.id()), Qt::UserRole);
        addr_item->setEditable(false);

        // Name
        auto* name_item = new QStandardItem(QString::fromStdString(func.name()));
        name_item->setEditable(false);

        // Size
        auto* size_item = new QStandardItem(QString::number(func.size()));
        size_item->setEditable(false);

        // Type
        QString type_str;
        switch (func.type()) {
            case analysis::FunctionType::Normal: type_str = "Normal"; break;
            case analysis::FunctionType::Import: type_str = "Import"; break;
            case analysis::FunctionType::Export: type_str = "Export"; break;
            case analysis::FunctionType::Thunk: type_str = "Thunk"; break;
            case analysis::FunctionType::RuntimeInit: type_str = "RuntimeInit"; break;
            case analysis::FunctionType::TlsCallback: type_str = "TlsCallback"; break;
            case analysis::FunctionType::Exception: type_str = "Exception"; break;
            case analysis::FunctionType::VirtualMethod: type_str = "VirtualMethod"; break;
        }
        auto* type_item = new QStandardItem(type_str);
        type_item->setEditable(false);

        row << addr_item << name_item << size_item << type_item;
        model_->appendRow(row);
    }

    // Resize columns to fit content
    for (int i = 0; i < 4; ++i) {
        tree_view_->resizeColumnToContents(i);
    }

    // Ensure name column has reasonable minimum width
    if (tree_view_->columnWidth(1) < 120) {
        tree_view_->setColumnWidth(1, 120);
    }
}

} // namespace picanha::ui
