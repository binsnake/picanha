#include <picanha/ui-qt/hex_widget.hpp>
#include <picanha/ui-qt/main_window.hpp>
#include <picanha/core/span.hpp>

#include <QPainter>
#include <QScrollBar>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QFontDatabase>

namespace picanha::ui {

HexWidget::HexWidget(MainWindow* window, QWidget* parent)
    : QAbstractScrollArea(parent)
    , window_(window)
{
    // Set up monospace font
    mono_font_ = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono_font_.setPointSize(10);
    setFont(mono_font_);

    // Style
    setStyleSheet(QString(R"(
        QAbstractScrollArea {
            background-color: %1;
            color: %2;
            border: none;
        }
        QScrollBar:vertical {
            background-color: #2d2d2d;
            width: 14px;
        }
        QScrollBar::handle:vertical {
            background-color: #5a5a5a;
            min-height: 20px;
        }
    )").arg(config_.color_background.name(), config_.color_text.name()));

    setFocusPolicy(Qt::StrongFocus);
    setMouseTracking(true);
}

HexWidget::~HexWidget() = default;

void HexWidget::gotoAddress(Address address) {
    current_address_ = address;
    ensureVisible(address);
    viewport()->update();
}

void HexWidget::scrollToAddress(Address address) {
    ensureVisible(address);
}

void HexWidget::selectRange(Address start, Address end) {
    selection_start_ = start;
    selection_end_ = end;
    viewport()->update();
}

void HexWidget::refresh() {
    if (!window_ || !window_->hasBinary()) {
        data_start_ = 0;
        data_end_ = 0;
        data_cache_.clear();
        return;
    }

    auto binary = window_->binary();

    // Find data range from all sections
    data_start_ = INVALID_ADDRESS;
    data_end_ = 0;

    for (const auto& section : binary->sections()) {
        if (data_start_ == INVALID_ADDRESS || section.virtual_address < data_start_) {
            data_start_ = section.virtual_address;
        }
        Address section_end = section.virtual_address + section.virtual_size;
        if (section_end > data_end_) {
            data_end_ = section_end;
        }
    }

    if (data_start_ == INVALID_ADDRESS) {
        data_start_ = binary->image_base();
        data_end_ = data_start_ + 0x1000;
    }

    current_address_ = data_start_;
    updateScrollBars();
    viewport()->update();
}

void HexWidget::paintEvent(QPaintEvent* event) {
    QPainter painter(viewport());
    painter.setFont(mono_font_);

    const int lh = lineHeight();
    const int first_row = verticalScrollBar()->value();
    const int visible_rows = viewport()->height() / lh + 2;

    // Draw background
    painter.fillRect(viewport()->rect(), config_.color_background);

    if (!window_ || !window_->hasBinary()) {
        painter.setPen(config_.color_text);
        painter.drawText(10, lh, tr("No binary loaded"));
        return;
    }

    auto binary = window_->binary();

    const int addr_width = addressColumnWidth();
    const int hex_width = hexColumnWidth();
    const int ascii_x = addr_width + hex_width + 20;

    for (int row = 0; row < visible_rows; ++row) {
        int abs_row = first_row + row;
        Address row_addr = data_start_ + abs_row * config_.bytes_per_row;

        if (row_addr >= data_end_) break;

        int y = row * lh;
        int text_y = y + lh - 4;

        // Highlight current line
        if (row_addr <= current_address_ && current_address_ < row_addr + config_.bytes_per_row) {
            painter.fillRect(0, y, viewport()->width(), lh, config_.color_current_line);
        }

        // Address
        int x = 5;
        painter.setPen(config_.color_address);
        painter.drawText(x, text_y, QString("%1").arg(row_addr, 16, 16, QChar('0')));
        x = addr_width + 5;

        // Read bytes for this row
        auto bytes_opt = binary->read(row_addr, config_.bytes_per_row);
        ByteSpan bytes = bytes_opt.value_or(ByteSpan{});

        // Hex bytes
        painter.setPen(config_.color_hex);
        QString hex_str;
        for (int i = 0; i < config_.bytes_per_row; ++i) {
            if (i < static_cast<int>(bytes.size())) {
                Address byte_addr = row_addr + i;
                bool selected = selection_start_ != INVALID_ADDRESS &&
                               byte_addr >= selection_start_ && byte_addr <= selection_end_;

                if (selected) {
                    int byte_x = x + i * fontMetrics().horizontalAdvance("00 ");
                    painter.fillRect(byte_x - 1, y, fontMetrics().horizontalAdvance("00"), lh,
                                   config_.color_selection);
                }

                hex_str += QString("%1 ").arg(bytes[i], 2, 16, QChar('0'));
            } else {
                hex_str += "   ";
            }

            // Add extra space every 8 bytes
            if ((i + 1) % 8 == 0 && i < config_.bytes_per_row - 1) {
                hex_str += " ";
            }
        }
        painter.drawText(x, text_y, hex_str);

        // ASCII
        if (config_.show_ascii) {
            QString ascii_str;
            for (std::size_t i = 0; i < bytes.size(); ++i) {
                char c = static_cast<char>(bytes[i]);
                if (c >= 32 && c < 127) {
                    ascii_str += c;
                } else {
                    ascii_str += '.';
                }
            }
            painter.setPen(config_.color_ascii);
            painter.drawText(ascii_x, text_y, ascii_str);
        }
    }

    // Draw separator line between hex and ASCII
    if (config_.show_ascii) {
        painter.setPen(config_.color_separator);
        int sep_x = ascii_x - 10;
        painter.drawLine(sep_x, 0, sep_x, viewport()->height());
    }
}

void HexWidget::resizeEvent(QResizeEvent* event) {
    QAbstractScrollArea::resizeEvent(event);
    updateScrollBars();
}

void HexWidget::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        Address addr = addressAtPosition(event->pos());
        if (addr != INVALID_ADDRESS) {
            current_address_ = addr;
            selection_start_ = addr;
            selection_end_ = addr;
            selecting_ = true;
            viewport()->update();
            emit addressSelected(addr);
        }
    }
    QAbstractScrollArea::mousePressEvent(event);
}

void HexWidget::mouseMoveEvent(QMouseEvent* event) {
    if (selecting_) {
        Address addr = addressAtPosition(event->pos());
        if (addr != INVALID_ADDRESS) {
            selection_end_ = addr;
            viewport()->update();
        }
    }
    QAbstractScrollArea::mouseMoveEvent(event);
}

void HexWidget::mouseReleaseEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        selecting_ = false;
    }
    QAbstractScrollArea::mouseReleaseEvent(event);
}

void HexWidget::keyPressEvent(QKeyEvent* event) {
    int step = 1;
    switch (event->key()) {
        case Qt::Key_Up:
            step = -config_.bytes_per_row;
            break;
        case Qt::Key_Down:
            step = config_.bytes_per_row;
            break;
        case Qt::Key_Left:
            step = -1;
            break;
        case Qt::Key_Right:
            step = 1;
            break;
        case Qt::Key_PageUp:
            step = -(viewport()->height() / lineHeight()) * config_.bytes_per_row;
            break;
        case Qt::Key_PageDown:
            step = (viewport()->height() / lineHeight()) * config_.bytes_per_row;
            break;
        default:
            QAbstractScrollArea::keyPressEvent(event);
            return;
    }

    Address new_addr = current_address_ + step;
    if (new_addr >= data_start_ && new_addr < data_end_) {
        current_address_ = new_addr;
        ensureVisible(current_address_);
        viewport()->update();
        emit addressSelected(current_address_);
    }
}

void HexWidget::wheelEvent(QWheelEvent* event) {
    QAbstractScrollArea::wheelEvent(event);
}

void HexWidget::updateScrollBars() {
    if (data_end_ <= data_start_) {
        verticalScrollBar()->setRange(0, 0);
        return;
    }

    int total_rows = (data_end_ - data_start_ + config_.bytes_per_row - 1) / config_.bytes_per_row;
    int visible_rows = viewport()->height() / lineHeight();

    verticalScrollBar()->setRange(0, std::max(0, total_rows - visible_rows));
    verticalScrollBar()->setPageStep(visible_rows);
}

int HexWidget::lineHeight() const {
    return fontMetrics().height() + 2;
}

int HexWidget::addressColumnWidth() const {
    return fontMetrics().horizontalAdvance("0000000000000000  ");
}

int HexWidget::hexColumnWidth() const {
    // bytes_per_row * "XX " + extra spaces for grouping
    int groups = config_.bytes_per_row / 8;
    return fontMetrics().horizontalAdvance(QString("00 ").repeated(config_.bytes_per_row)) +
           fontMetrics().horizontalAdvance(" ") * (groups - 1);
}

int HexWidget::asciiColumnWidth() const {
    return fontMetrics().horizontalAdvance(QString("X").repeated(config_.bytes_per_row));
}

Address HexWidget::addressAtPosition(const QPoint& pos) const {
    int row = rowAtY(pos.y());
    int byte = byteAtX(pos.x());

    if (row < 0 || byte < 0 || byte >= config_.bytes_per_row) {
        return INVALID_ADDRESS;
    }

    int scroll = verticalScrollBar()->value();
    Address addr = data_start_ + (scroll + row) * config_.bytes_per_row + byte;

    if (addr >= data_end_) {
        return INVALID_ADDRESS;
    }

    return addr;
}

int HexWidget::rowAtY(int y) const {
    return y / lineHeight();
}

int HexWidget::byteAtX(int x) const {
    int hex_start = addressColumnWidth() + 5;
    int hex_end = hex_start + hexColumnWidth();

    if (x < hex_start || x > hex_end) {
        return -1;
    }

    int rel_x = x - hex_start;
    int char_width = fontMetrics().horizontalAdvance("00 ");

    return rel_x / char_width;
}

void HexWidget::ensureVisible(Address address) {
    if (address < data_start_ || address >= data_end_) return;

    int row = (address - data_start_) / config_.bytes_per_row;
    int scroll = verticalScrollBar()->value();
    int visible = viewport()->height() / lineHeight();

    if (row < scroll) {
        verticalScrollBar()->setValue(row);
    } else if (row >= scroll + visible) {
        verticalScrollBar()->setValue(row - visible + 1);
    }
}

} // namespace picanha::ui
