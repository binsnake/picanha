#include <picanha/ui-qt/imports_widget.hpp>
#include <picanha/ui-qt/main_window.hpp>

#include <QVBoxLayout>
#include <QHeaderView>

namespace picanha::ui {

ImportsWidget::ImportsWidget(MainWindow* window, QWidget* parent)
    : QWidget(parent)
    , window_(window)
    , filter_edit_(new QLineEdit(this))
    , tree_view_(new QTreeView(this))
    , model_(new QStandardItemModel(this))
    , proxy_model_(new QSortFilterProxyModel(this))
{
    setupUI();
}

ImportsWidget::~ImportsWidget() = default;

void ImportsWidget::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(2);

    // Filter
    filter_edit_->setPlaceholderText(tr("Filter imports..."));
    filter_edit_->setClearButtonEnabled(true);
    layout->addWidget(filter_edit_);

    // Tree view
    proxy_model_->setSourceModel(model_);
    proxy_model_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_model_->setRecursiveFilteringEnabled(true);

    tree_view_->setModel(proxy_model_);
    tree_view_->setAlternatingRowColors(true);
    tree_view_->setSelectionMode(QAbstractItemView::SingleSelection);
    tree_view_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tree_view_->setHeaderHidden(true);

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
        QTreeView::branch:has-children:!has-siblings:closed,
        QTreeView::branch:closed:has-children:has-siblings {
            border-image: none;
            image: url(:/icons/branch-closed.png);
        }
        QTreeView::branch:open:has-children:!has-siblings,
        QTreeView::branch:open:has-children:has-siblings {
            border-image: none;
            image: url(:/icons/branch-open.png);
        }
        QLineEdit {
            background-color: #2d2d2d;
            color: #d4d4d4;
            border: 1px solid #3d3d3d;
            padding: 4px;
        }
    )");

    // Connections
    connect(filter_edit_, &QLineEdit::textChanged, this, &ImportsWidget::onFilterChanged);
    connect(tree_view_->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &ImportsWidget::onSelectionChanged);
    connect(tree_view_, &QTreeView::doubleClicked, this, &ImportsWidget::onDoubleClicked);
}

void ImportsWidget::refresh() {
    populateModel();
}

void ImportsWidget::onSelectionChanged() {
    auto indices = tree_view_->selectionModel()->selectedRows();
    if (indices.isEmpty()) return;

    auto source_idx = proxy_model_->mapToSource(indices.first());
    auto* item = model_->itemFromIndex(source_idx);
    if (item && item->data(Qt::UserRole).isValid()) {
        Address addr = item->data(Qt::UserRole).toULongLong();
        if (addr != INVALID_ADDRESS) {
            emit importSelected(addr);
        }
    }
}

void ImportsWidget::onDoubleClicked(const QModelIndex& index) {
    auto source_idx = proxy_model_->mapToSource(index);
    auto* item = model_->itemFromIndex(source_idx);
    if (item && item->data(Qt::UserRole).isValid()) {
        Address addr = item->data(Qt::UserRole).toULongLong();
        if (addr != INVALID_ADDRESS) {
            emit importSelected(addr);
        }
    }
}

void ImportsWidget::onFilterChanged(const QString& text) {
    proxy_model_->setFilterWildcard(text);
    if (!text.isEmpty()) {
        tree_view_->expandAll();
    }
}

void ImportsWidget::populateModel() {
    model_->clear();

    if (!window_ || !window_->hasBinary()) return;

    auto binary = window_->binary();
    const auto* import_info = binary->imports();
    if (!import_info) return;

    // Create tree structure grouped by module
    for (const auto& module : import_info->modules) {
        auto* module_item = new QStandardItem(QString::fromStdString(module.name));
        module_item->setEditable(false);

        for (const auto& func : module.functions) {
            QString import_text;
            if (func.by_ordinal && !func.has_name()) {
                import_text = QString("Ordinal %1").arg(func.ordinal);
            } else {
                // Convert RVA to VA using image base
                Address iat_va = binary->image_base() + func.iat_rva;
                import_text = QString("0x%1  %2")
                    .arg(iat_va, 16, 16, QChar('0'))
                    .arg(QString::fromStdString(func.name));
            }

            auto* import_item = new QStandardItem(import_text);
            Address iat_va = binary->image_base() + func.iat_rva;
            import_item->setData(static_cast<qulonglong>(iat_va), Qt::UserRole);
            import_item->setEditable(false);

            module_item->appendRow(import_item);
        }

        model_->appendRow(module_item);
    }

    tree_view_->expandAll();
}

} // namespace picanha::ui
