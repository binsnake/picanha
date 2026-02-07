#include <picanha/ui-qt/disasm_widget.hpp>
#include <picanha/ui-qt/main_window.hpp>
#include <picanha/core/span.hpp>

#include <QPainter>
#include <QScrollBar>
#include <QMouseEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QClipboard>
#include <QApplication>
#include <QFontDatabase>

namespace picanha::ui {

// Symbol resolver implementation
std::optional<iced_x86::SymbolResult> WidgetSymbolResolver::try_get_symbol(
    const iced_x86::Instruction& instruction,
    int operand,
    int instruction_operand,
    uint64_t address,
    int address_size)
{
    if (!window_ || !window_->hasBinary()) {
        return std::nullopt;
    }

    // Check symbol table
    auto* symbol = window_->symbols().find_at(address);
    if (symbol) {
        return iced_x86::SymbolResult{address, symbol->name};
    }

    // Check functions
    for (const auto& func : window_->functions()) {
        if (func.entry_address() == address) {
            return iced_x86::SymbolResult{address, func.name()};
        }
    }

    return std::nullopt;
}

// DisasmWidget implementation

DisasmWidget::DisasmWidget(MainWindow* window, QWidget* parent)
    : QAbstractScrollArea(parent)
    , window_(window)
    , symbol_resolver_(window)
    , formatter_()
{
    // Set up monospace font
    mono_font_ = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono_font_.setPointSize(10);
    setFont(mono_font_);

    // Configure formatter
    formatter_.options().set_space_after_operand_separator(true);
    formatter_.options().set_hex_prefix("0x");
    formatter_.options().set_hex_suffix("");
    formatter_.options().set_uppercase_hex(false);
    formatter_.options().set_leading_zeros(false);
    formatter_.set_symbol_resolver(&symbol_resolver_);

    // Set up viewport
    setViewportMargins(0, 0, 0, 0);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);

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
        QScrollBar::handle:vertical:hover {
            background-color: #6a6a6a;
        }
    )").arg(config_.color_background.name(), config_.color_text.name()));

    setFocusPolicy(Qt::StrongFocus);
}

DisasmWidget::~DisasmWidget() = default;

void DisasmWidget::gotoAddress(Address address) {
    goto_address_ = address;

    // Find line with this address
    auto it = address_to_line_.find(address);
    if (it != address_to_line_.end()) {
        selectLine(it->second);
        ensureVisible(it->second);
    } else {
        // Address not in current view, need to regenerate
        refresh();
    }
}

void DisasmWidget::scrollToAddress(Address address) {
    auto it = address_to_line_.find(address);
    if (it != address_to_line_.end()) {
        ensureVisible(it->second);
    }
}

void DisasmWidget::centerOnAddress(Address address) {
    auto it = address_to_line_.find(address);
    if (it != address_to_line_.end()) {
        int visible_lines = viewport()->height() / lineHeight();
        int target_scroll = static_cast<int>(it->second) - visible_lines / 2;
        verticalScrollBar()->setValue(std::max(0, target_scroll));
    }
}

void DisasmWidget::selectLine(std::size_t line_index) {
    if (line_index >= lines_.size()) return;

    // Deselect old
    if (selected_line_ < lines_.size()) {
        lines_[selected_line_].is_selected = false;
    }

    selected_line_ = line_index;
    lines_[line_index].is_selected = true;
    selected_address_ = lines_[line_index].address;

    viewport()->update();
    emit addressSelected(selected_address_);
}

void DisasmWidget::selectAddress(Address address) {
    auto it = address_to_line_.find(address);
    if (it != address_to_line_.end()) {
        selectLine(it->second);
    }
}

Address DisasmWidget::selectedAddress() const {
    return selected_address_;
}

void DisasmWidget::refresh() {
    generateAllLines();
    calculateFlowArrows();
    updateScrollBars();
    viewport()->update();

    // Jump to goto address if set
    if (goto_address_) {
        auto it = address_to_line_.find(*goto_address_);
        if (it != address_to_line_.end()) {
            selectLine(it->second);
            ensureVisible(it->second);
        }
        goto_address_.reset();
    }
}

void DisasmWidget::generateAllLines() {
    lines_.clear();
    address_to_line_.clear();
    call_targets_.clear();
    jump_targets_.clear();

    if (!window_ || !window_->hasBinary()) {
        return;
    }

    auto binary = window_->binary();
    const auto& functions = window_->functions();

    // If we have functions, generate function-based view
    if (!functions.empty()) {
        for (const auto& func : functions) {
            generateFunctionLines(func);
        }
    } else {
        // No functions yet - show a message instead of attempting linear disassembly
        // Linear disassembly of large binaries can be very slow
        DisasmLine info_line;
        info_line.type = DisasmLineType::Comment;
        info_line.comment = tr("; Binary loaded. Run Analysis (F5) to detect functions and disassemble.");
        lines_.push_back(std::move(info_line));
    }
}

void DisasmWidget::generateFunctionLines(const analysis::Function& func) {
    auto binary = window_->binary();
    if (!binary) return;

    // Function header
    lines_.push_back(makeFunctionHeader(func));

    // Collect jump targets within function
    std::unordered_set<Address> local_targets;

    // First pass: collect targets
    Address addr = func.entry_address();
    Address end = func.entry_address() + func.size();

    while (addr < end) {
        auto bytes_opt = binary->read(addr, 15);
        if (!bytes_opt || bytes_opt->empty()) break;
        auto bytes = *bytes_opt;

        Instruction instr = decoder_.decode(bytes, addr);
        if (instr.is_valid()) {
            Address target = instr.branch_target();
            if (instr.is_branch() && target != INVALID_ADDRESS) {
                if (target >= func.entry_address() && target < end) {
                    local_targets.insert(target);
                }
            }
            addr += instr.length();
        } else {
            addr++;
        }
    }

    // Second pass: generate lines
    addr = func.entry_address();
    while (addr < end) {
        // Insert label if this is a jump target
        if (local_targets.count(addr)) {
            auto label = makeLabelLine(addr, QString("loc_%1").arg(addr, 0, 16));
            lines_.push_back(std::move(label));
        }

        auto bytes_opt = binary->read(addr, 15);
        if (!bytes_opt || bytes_opt->empty()) break;
        auto bytes = *bytes_opt;

        Instruction instr = decoder_.decode(bytes, addr);
        if (instr.is_valid()) {
            auto line = makeInstructionLine(instr, ByteSpan(bytes.data(), instr.length()));

            // Mark as call/jump target
            if (local_targets.count(addr)) {
                line.is_jump_target = true;
            }

            address_to_line_[addr] = lines_.size();
            lines_.push_back(std::move(line));
            addr += instr.length();
        } else {
            addr++;
        }
    }

    // Empty line after function
    DisasmLine empty;
    empty.type = DisasmLineType::Empty;
    lines_.push_back(std::move(empty));
}

DisasmLine DisasmWidget::makeInstructionLine(const Instruction& instr, ByteSpan bytes) {
    DisasmLine line;
    line.type = DisasmLineType::Instruction;
    line.address = instr.ip();

    // Copy bytes
    line.bytes.assign(bytes.data(), bytes.data() + bytes.size());

    // Format instruction
    std::string formatted = formatter_.format_to_string(instr.raw());

    // Split into mnemonic and operands
    auto space_pos = formatted.find(' ');
    if (space_pos != std::string::npos) {
        line.mnemonic = QString::fromStdString(formatted.substr(0, space_pos));
        line.operands = QString::fromStdString(formatted.substr(space_pos + 1));
    } else {
        line.mnemonic = QString::fromStdString(formatted);
    }

    // Check instruction type
    line.is_call = instr.is_call();
    line.is_jump = instr.is_branch() && !instr.is_call();
    line.target_address = instr.branch_target();

    // Get xref count
    if (window_) {
        auto xrefs = window_->xrefs().get_refs_to(instr.ip());
        line.xref_count = xrefs.size();

        if (!xrefs.empty() && config_.show_xrefs) {
            line.comment = formatXRefComment(instr.ip());
        }
    }

    return line;
}

DisasmLine DisasmWidget::makeLabelLine(Address address, const QString& name) {
    DisasmLine line;
    line.type = DisasmLineType::Label;
    line.address = address;
    line.label = name;
    return line;
}

DisasmLine DisasmWidget::makeFunctionHeader(const analysis::Function& func) {
    DisasmLine line;
    line.type = DisasmLineType::FunctionHeader;
    line.address = func.entry_address();
    line.label = QString::fromStdString(func.name());
    return line;
}

DisasmLine DisasmWidget::makeSectionHeader(const QString& name) {
    DisasmLine line;
    line.type = DisasmLineType::SectionHeader;
    line.label = name;
    return line;
}

DisasmLine DisasmWidget::makeAlignmentLine(Address address, Size size) {
    DisasmLine line;
    line.type = DisasmLineType::Alignment;
    line.address = address;
    line.label = QString("align %1").arg(size);
    return line;
}

QString DisasmWidget::formatXRefComment(Address address) const {
    if (!window_) return QString();

    auto xrefs = window_->xrefs().get_refs_to(address);
    if (xrefs.empty()) return QString();

    QString comment = QString("; xref: ");
    int count = 0;
    for (const auto& xref : xrefs) {
        if (count > 0) comment += ", ";
        if (count >= 3) {
            comment += QString("... (%1 more)").arg(xrefs.size() - 3);
            break;
        }
        comment += QString("0x%1").arg(xref.from, 0, 16);
        count++;
    }
    return comment;
}

void DisasmWidget::paintEvent(QPaintEvent* event) {
    QPainter painter(viewport());
    painter.setFont(mono_font_);

    // Draw background
    painter.fillRect(viewport()->rect(), config_.color_background);

    // Show message if no content
    if (lines_.empty()) {
        painter.setPen(QColor(0x80, 0x80, 0x80));
        QString message = window_->hasBinary()
            ? tr("Run Analysis (F5) to disassemble")
            : tr("Open a binary file to begin\n\nFile > Open Binary  or  Ctrl+O\n\nYou can also drag and drop a file here");
        QRect textRect = viewport()->rect();
        painter.drawText(textRect, Qt::AlignCenter, message);
        return;
    }

    const int lh = lineHeight();
    const int first_visible = verticalScrollBar()->value();
    const int visible_count = viewport()->height() / lh + 2;
    const int last_visible = std::min(first_visible + visible_count, static_cast<int>(lines_.size()));

    // Calculate column positions
    int x = 5;
    const int addr_width = addressColumnWidth();
    const int bytes_width = bytesColumnWidth();
    const int arrow_width = config_.show_flow_arrows ? arrowColumnWidth() : 0;
    const int mnemonic_x = x + addr_width + bytes_width + arrow_width + 20;

    // Draw flow arrows first (behind text)
    if (config_.show_flow_arrows) {
        paintFlowArrows(painter, first_visible, last_visible);
    }

    // Draw lines
    for (int i = first_visible; i < last_visible; ++i) {
        const auto& line = lines_[i];
        int y = (i - first_visible) * lh;
        int text_y = y + lh - 4;

        // Selection background
        if (line.is_selected) {
            painter.fillRect(0, y, viewport()->width(), lh, config_.color_selection);
        } else if (i == static_cast<int>(selected_line_)) {
            painter.fillRect(0, y, viewport()->width(), lh, config_.color_current_line);
        }

        x = 5;

        switch (line.type) {
            case DisasmLineType::Instruction: {
                // Address
                if (config_.show_addresses && line.address != INVALID_ADDRESS) {
                    painter.setPen(config_.color_address);
                    painter.drawText(x, text_y, QString("%1").arg(line.address, 16, 16, QChar('0')));
                }
                x += addr_width;

                // Bytes
                if (config_.show_bytes) {
                    painter.setPen(config_.color_bytes);
                    QString bytes_str;
                    for (auto b : line.bytes) {
                        bytes_str += QString("%1 ").arg(b, 2, 16, QChar('0'));
                    }
                    painter.drawText(x, text_y, bytes_str.trimmed());
                }
                x = mnemonic_x;

                // Mnemonic
                QColor mnemonic_color = config_.color_mnemonic;
                if (line.is_call) mnemonic_color = config_.color_call;
                else if (line.is_jump) mnemonic_color = config_.color_jump;
                painter.setPen(mnemonic_color);
                painter.drawText(x, text_y, line.mnemonic);
                x += 80;

                // Operands
                painter.setPen(config_.color_text);
                painter.drawText(x, text_y, line.operands);
                x += painter.fontMetrics().horizontalAdvance(line.operands) + 20;

                // Comment
                if (!line.comment.isEmpty()) {
                    painter.setPen(config_.color_comment);
                    painter.drawText(x, text_y, line.comment);
                }
                break;
            }

            case DisasmLineType::FunctionHeader: {
                painter.setPen(config_.color_label);
                QString header = QString("; =============== %1 ===============").arg(line.label);
                painter.drawText(x, text_y, header);
                break;
            }

            case DisasmLineType::Label: {
                if (config_.show_addresses && line.address != INVALID_ADDRESS) {
                    painter.setPen(config_.color_address);
                    painter.drawText(x, text_y, QString("%1").arg(line.address, 16, 16, QChar('0')));
                }
                x += addr_width + bytes_width + arrow_width + 10;
                painter.setPen(config_.color_label);
                painter.drawText(x, text_y, line.label + ":");
                break;
            }

            case DisasmLineType::SectionHeader: {
                painter.setPen(config_.color_comment);
                painter.drawText(x, text_y, QString("; === Section: %1 ===").arg(line.label));
                break;
            }

            case DisasmLineType::Comment: {
                painter.setPen(config_.color_comment);
                painter.drawText(x, text_y, "; " + line.comment);
                break;
            }

            case DisasmLineType::Alignment: {
                x += addr_width + bytes_width + arrow_width + 20;
                painter.setPen(config_.color_comment);
                painter.drawText(x, text_y, line.label);
                break;
            }

            default:
                break;
        }
    }
}

void DisasmWidget::resizeEvent(QResizeEvent* event) {
    QAbstractScrollArea::resizeEvent(event);
    updateScrollBars();
}

void DisasmWidget::mousePressEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        std::size_t line = lineAtPosition(event->pos().y());
        if (line < lines_.size()) {
            selectLine(line);
        }
    }
    QAbstractScrollArea::mousePressEvent(event);
}

void DisasmWidget::mouseDoubleClickEvent(QMouseEvent* event) {
    if (event->button() == Qt::LeftButton) {
        std::size_t line = lineAtPosition(event->pos().y());
        if (line < lines_.size()) {
            const auto& l = lines_[line];
            if (l.target_address != INVALID_ADDRESS) {
                window_->navigateTo(l.target_address);
            }
        }
    }
    QAbstractScrollArea::mouseDoubleClickEvent(event);
}

void DisasmWidget::keyPressEvent(QKeyEvent* event) {
    switch (event->key()) {
        case Qt::Key_Up:
            if (selected_line_ > 0) {
                selectLine(selected_line_ - 1);
                ensureVisible(selected_line_);
            }
            break;

        case Qt::Key_Down:
            if (selected_line_ + 1 < lines_.size()) {
                selectLine(selected_line_ + 1);
                ensureVisible(selected_line_);
            }
            break;

        case Qt::Key_PageUp: {
            int page_size = viewport()->height() / lineHeight();
            std::size_t new_line = selected_line_ > static_cast<std::size_t>(page_size)
                ? selected_line_ - page_size : 0;
            selectLine(new_line);
            ensureVisible(new_line);
            break;
        }

        case Qt::Key_PageDown: {
            int page_size = viewport()->height() / lineHeight();
            std::size_t new_line = std::min(selected_line_ + page_size, lines_.size() - 1);
            selectLine(new_line);
            ensureVisible(new_line);
            break;
        }

        case Qt::Key_Home:
            if (event->modifiers() & Qt::ControlModifier) {
                selectLine(0);
                ensureVisible(0);
            }
            break;

        case Qt::Key_End:
            if (event->modifiers() & Qt::ControlModifier && !lines_.empty()) {
                selectLine(lines_.size() - 1);
                ensureVisible(lines_.size() - 1);
            }
            break;

        case Qt::Key_Return:
        case Qt::Key_Enter: {
            if (selected_line_ < lines_.size()) {
                const auto& l = lines_[selected_line_];
                if (l.target_address != INVALID_ADDRESS) {
                    window_->navigateTo(l.target_address);
                }
            }
            break;
        }

        case Qt::Key_G:
            if (!(event->modifiers() & Qt::ControlModifier)) {
                // Go to address
                window_->onGotoAddress();
            }
            break;

        case Qt::Key_C:
            if (event->modifiers() & Qt::ControlModifier) {
                // Copy address
                if (selected_line_ < lines_.size()) {
                    auto addr = lines_[selected_line_].address;
                    if (addr != INVALID_ADDRESS) {
                        QApplication::clipboard()->setText(
                            QString("0x%1").arg(addr, 16, 16, QChar('0')));
                    }
                }
            }
            break;

        default:
            QAbstractScrollArea::keyPressEvent(event);
    }
}

void DisasmWidget::wheelEvent(QWheelEvent* event) {
    QAbstractScrollArea::wheelEvent(event);
}

void DisasmWidget::contextMenuEvent(QContextMenuEvent* event) {
    QMenu menu(this);

    auto* copyAddr = menu.addAction(tr("Copy Address"));
    auto* copyLine = menu.addAction(tr("Copy Line"));
    menu.addSeparator();
    auto* gotoAddr = menu.addAction(tr("Go to Address..."));

    if (selected_line_ < lines_.size()) {
        const auto& line = lines_[selected_line_];
        if (line.target_address != INVALID_ADDRESS) {
            menu.addSeparator();
            auto* followTarget = menu.addAction(tr("Follow Target"));
            connect(followTarget, &QAction::triggered, [this, &line]() {
                window_->navigateTo(line.target_address);
            });
        }
    }

    connect(copyAddr, &QAction::triggered, [this]() {
        if (selected_line_ < lines_.size()) {
            auto addr = lines_[selected_line_].address;
            if (addr != INVALID_ADDRESS) {
                QApplication::clipboard()->setText(
                    QString("0x%1").arg(addr, 16, 16, QChar('0')));
            }
        }
    });

    connect(copyLine, &QAction::triggered, [this]() {
        if (selected_line_ < lines_.size()) {
            const auto& line = lines_[selected_line_];
            QString text = QString("%1  %2 %3")
                .arg(line.address, 16, 16, QChar('0'))
                .arg(line.mnemonic)
                .arg(line.operands);
            QApplication::clipboard()->setText(text);
        }
    });

    connect(gotoAddr, &QAction::triggered, [this]() {
        window_->onGotoAddress();
    });

    menu.exec(event->globalPos());
}

void DisasmWidget::updateScrollBars() {
    int total_height = static_cast<int>(lines_.size()) * lineHeight();
    int visible_height = viewport()->height();

    verticalScrollBar()->setRange(0, std::max(0, static_cast<int>(lines_.size()) - visible_height / lineHeight()));
    verticalScrollBar()->setPageStep(visible_height / lineHeight());
}

int DisasmWidget::lineHeight() const {
    return fontMetrics().height() + 2;
}

int DisasmWidget::addressColumnWidth() const {
    return config_.show_addresses ? fontMetrics().horizontalAdvance("0000000000000000  ") : 0;
}

int DisasmWidget::bytesColumnWidth() const {
    return config_.show_bytes ? fontMetrics().horizontalAdvance("00 00 00 00 00 00 00 00  ") : 0;
}

int DisasmWidget::arrowColumnWidth() const {
    return 60;
}

std::size_t DisasmWidget::lineAtPosition(int y) const {
    int scroll = verticalScrollBar()->value();
    return scroll + y / lineHeight();
}

void DisasmWidget::ensureVisible(std::size_t line) {
    int scroll = verticalScrollBar()->value();
    int visible = viewport()->height() / lineHeight();

    if (static_cast<int>(line) < scroll) {
        verticalScrollBar()->setValue(static_cast<int>(line));
    } else if (static_cast<int>(line) >= scroll + visible) {
        verticalScrollBar()->setValue(static_cast<int>(line) - visible + 1);
    }
}

void DisasmWidget::calculateFlowArrows() {
    flow_arrows_.clear();

    // Build arrows for jumps within visible functions
    for (std::size_t i = 0; i < lines_.size(); ++i) {
        const auto& line = lines_[i];
        if (line.type != DisasmLineType::Instruction) continue;
        if (!line.is_jump || line.target_address == INVALID_ADDRESS) continue;

        // Find target line
        auto it = address_to_line_.find(line.target_address);
        if (it == address_to_line_.end()) continue;

        FlowArrow arrow;
        arrow.from_line = i;
        arrow.to_line = it->second;
        arrow.is_forward = it->second > i;
        arrow.is_conditional = line.mnemonic.startsWith('j') && line.mnemonic != "jmp";
        arrow.depth = 0;

        flow_arrows_.push_back(arrow);
    }

    // Calculate depths to avoid overlapping
    for (auto& arrow : flow_arrows_) {
        int depth = 0;
        for (const auto& other : flow_arrows_) {
            if (&arrow == &other) continue;

            std::size_t a_min = std::min(arrow.from_line, arrow.to_line);
            std::size_t a_max = std::max(arrow.from_line, arrow.to_line);
            std::size_t o_min = std::min(other.from_line, other.to_line);
            std::size_t o_max = std::max(other.from_line, other.to_line);

            // Check overlap
            if (a_min < o_max && a_max > o_min) {
                depth = std::max(depth, other.depth + 1);
            }
        }
        arrow.depth = depth;
    }
}

void DisasmWidget::paintFlowArrows(QPainter& painter, int first_visible, int last_visible) {
    const int lh = lineHeight();
    const int x_base = addressColumnWidth() + bytesColumnWidth() + 10;
    const int x_step = 8;

    for (const auto& arrow : flow_arrows_) {
        int from = static_cast<int>(arrow.from_line);
        int to = static_cast<int>(arrow.to_line);

        // Skip if not visible
        int min_line = std::min(from, to);
        int max_line = std::max(from, to);
        if (max_line < first_visible || min_line > last_visible) continue;

        // Calculate positions
        int y1 = (from - first_visible) * lh + lh / 2;
        int y2 = (to - first_visible) * lh + lh / 2;
        int x = x_base + arrow.depth * x_step;

        QColor color = arrow.is_forward ? config_.color_flow_arrow : config_.color_flow_arrow_back;
        painter.setPen(QPen(color, 1));

        // Draw arrow
        painter.drawLine(x, y1, x, y2);
        painter.drawLine(x, y1, x + 5, y1);
        painter.drawLine(x, y2, x + 5, y2);

        // Arrow head
        if (arrow.is_forward) {
            painter.drawLine(x + 5, y2, x + 2, y2 - 3);
            painter.drawLine(x + 5, y2, x + 2, y2 + 3);
        } else {
            painter.drawLine(x + 5, y2, x + 2, y2 - 3);
            painter.drawLine(x + 5, y2, x + 2, y2 + 3);
        }
    }
}

} // namespace picanha::ui
