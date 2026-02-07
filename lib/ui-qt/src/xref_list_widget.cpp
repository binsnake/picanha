#include <picanha/ui-qt/xref_list_widget.hpp>
#include <picanha/ui-qt/main_window.hpp>

#include <QVBoxLayout>
#include <QHeaderView>
#include <QLabel>

namespace picanha::ui {

XRefListWidget::XRefListWidget(MainWindow* window, QWidget* parent)
    : QWidget(parent)
    , window_(window)
    , mode_combo_(new QComboBox(this))
    , tree_view_(new QTreeView(this))
    , model_(new QStandardItemModel(this))
{
    setupUI();
}

XRefListWidget::~XRefListWidget() = default;

void XRefListWidget::setupUI() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(2);

    // Mode selector
    mode_combo_->addItem(tr("References TO"), static_cast<int>(XRefMode::ToAddress));
    mode_combo_->addItem(tr("References FROM"), static_cast<int>(XRefMode::FromAddress));
    mode_combo_->addItem(tr("Both"), static_cast<int>(XRefMode::Both));
    layout->addWidget(mode_combo_);

    // Tree view
    tree_view_->setModel(model_);
    tree_view_->setRootIsDecorated(false);
    tree_view_->setAlternatingRowColors(true);
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
        QComboBox {
            background-color: #2d2d2d;
            color: #d4d4d4;
            border: 1px solid #3d3d3d;
            padding: 4px;
        }
        QComboBox::drop-down {
            border: none;
        }
        QComboBox QAbstractItemView {
            background-color: #2d2d2d;
            color: #d4d4d4;
            selection-background-color: #264f78;
        }
    )");

    // Set up model headers
    model_->setHorizontalHeaderLabels({tr("From"), tr("To"), tr("Type")});

    // Connections
    connect(mode_combo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &XRefListWidget::onModeChanged);
    connect(tree_view_->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &XRefListWidget::onSelectionChanged);
    connect(tree_view_, &QTreeView::doubleClicked, this, &XRefListWidget::onDoubleClicked);
}

void XRefListWidget::setAddress(Address address) {
    current_address_ = address;
    populateModel();
}

void XRefListWidget::setMode(XRefMode mode) {
    mode_ = mode;
    mode_combo_->setCurrentIndex(mode_combo_->findData(static_cast<int>(mode)));
    populateModel();
}

void XRefListWidget::refresh() {
    populateModel();
}

void XRefListWidget::onSelectionChanged() {
    auto indices = tree_view_->selectionModel()->selectedRows();
    if (indices.isEmpty()) return;

    Address addr = model_->data(indices.first(), Qt::UserRole).toULongLong();
    if (addr != INVALID_ADDRESS) {
        emit xrefSelected(addr);
    }
}

void XRefListWidget::onDoubleClicked(const QModelIndex& index) {
    Address addr = model_->data(model_->index(index.row(), 0), Qt::UserRole).toULongLong();
    if (addr != INVALID_ADDRESS) {
        emit xrefSelected(addr);
    }
}

void XRefListWidget::onModeChanged(int index) {
    mode_ = static_cast<XRefMode>(mode_combo_->itemData(index).toInt());
    populateModel();
}

void XRefListWidget::populateModel() {
    model_->removeRows(0, model_->rowCount());

    if (!window_ || current_address_ == INVALID_ADDRESS) return;

    std::vector<analysis::XRef> xrefs;

    if (mode_ == XRefMode::ToAddress || mode_ == XRefMode::Both) {
        auto to_refs = window_->xrefs().get_refs_to(current_address_);
        xrefs.insert(xrefs.end(), to_refs.begin(), to_refs.end());
    }

    if (mode_ == XRefMode::FromAddress || mode_ == XRefMode::Both) {
        auto from_refs = window_->xrefs().get_refs_from(current_address_);
        xrefs.insert(xrefs.end(), from_refs.begin(), from_refs.end());
    }

    for (const auto& xref : xrefs) {
        QList<QStandardItem*> row;

        // From
        auto* from_item = new QStandardItem(QString("0x%1").arg(xref.from, 16, 16, QChar('0')));
        from_item->setData(static_cast<qulonglong>(xref.from), Qt::UserRole);
        from_item->setEditable(false);

        // To
        auto* to_item = new QStandardItem(QString("0x%1").arg(xref.to, 16, 16, QChar('0')));
        to_item->setEditable(false);

        // Type - use the helper function for consistent naming
        QString type_str = QString::fromLatin1(analysis::xref_type_name(xref.type));
        auto* type_item = new QStandardItem(type_str);
        type_item->setEditable(false);

        row << from_item << to_item << type_item;
        model_->appendRow(row);
    }

    tree_view_->resizeColumnToContents(0);
    tree_view_->resizeColumnToContents(1);
    tree_view_->resizeColumnToContents(2);
}

} // namespace picanha::ui
