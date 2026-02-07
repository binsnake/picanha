#pragma once

#include <picanha/core/types.hpp>
#include <picanha/core/instruction.hpp>
#include <picanha/loader/binary.hpp>
#include <picanha/analysis/function.hpp>
#include <picanha/disasm/decoder.hpp>
#include <iced_x86/iced_x86.hpp>

#include <QWidget>
#include <QAbstractScrollArea>
#include <QFont>
#include <QColor>
#include <QTimer>

#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <optional>

namespace picanha::ui {

class MainWindow;

// Line types in the disassembly view
enum class DisasmLineType {
    Instruction,
    Label,
    FunctionHeader,
    FunctionEnd,
    SectionHeader,
    Comment,
    Data,
    Alignment,
    Separator,
    Empty,
};

// A single line in the disassembly listing
struct DisasmLine {
    DisasmLineType type{DisasmLineType::Empty};
    Address address{INVALID_ADDRESS};

    // For instructions
    std::vector<std::uint8_t> bytes;
    QString mnemonic;
    QString operands;
    QString comment;

    // For labels/functions
    QString label;

    // Target address for calls/jumps
    Address target_address{INVALID_ADDRESS};
    bool is_call{false};
    bool is_jump{false};
    bool is_data_ref{false};

    // Cross-references
    std::size_t xref_count{0};

    // Flags
    bool is_call_target{false};
    bool is_jump_target{false};
    bool is_selected{false};
};

// Control flow arrow
struct FlowArrow {
    std::size_t from_line;
    std::size_t to_line;
    int depth;
    bool is_forward;
    bool is_conditional;
};

// Disassembly widget configuration
struct DisasmConfig {
    bool show_addresses{true};
    bool show_bytes{true};
    bool show_xrefs{true};
    bool show_flow_arrows{true};
    int bytes_per_line{8};

    // Colors
    QColor color_background{0x1e, 0x1e, 0x1e};
    QColor color_text{0xd4, 0xd4, 0xd4};
    QColor color_address{0x80, 0x80, 0x80};
    QColor color_bytes{0x60, 0x60, 0x60};
    QColor color_mnemonic{0x56, 0x9c, 0xd6};
    QColor color_register{0x4e, 0xc9, 0xb0};
    QColor color_immediate{0xb5, 0xce, 0xa8};
    QColor color_memory{0xce, 0x91, 0x78};
    QColor color_comment{0x6a, 0x99, 0x55};
    QColor color_label{0xdc, 0xdc, 0xaa};
    QColor color_string{0xce, 0x91, 0x78};
    QColor color_selection{0x26, 0x4f, 0x78};
    QColor color_current_line{0x2d, 0x2d, 0x2d};
    QColor color_call{0xdc, 0xdc, 0xaa};
    QColor color_jump{0x56, 0x9c, 0xd6};
    QColor color_flow_arrow{0x56, 0x9c, 0xd6};
    QColor color_flow_arrow_back{0xce, 0x91, 0x78};
};

// Custom symbol resolver
class WidgetSymbolResolver : public iced_x86::SymbolResolver {
public:
    explicit WidgetSymbolResolver(MainWindow* window) : window_(window) {}

    [[nodiscard]] std::optional<iced_x86::SymbolResult> try_get_symbol(
        const iced_x86::Instruction& instruction,
        int operand,
        int instruction_operand,
        uint64_t address,
        int address_size) override;

private:
    MainWindow* window_;
};

// Disassembly widget - shows disassembled code
class DisasmWidget : public QAbstractScrollArea {
    Q_OBJECT

public:
    explicit DisasmWidget(MainWindow* window, QWidget* parent = nullptr);
    ~DisasmWidget() override;

    // Navigation
    void gotoAddress(Address address);
    void scrollToAddress(Address address);
    void centerOnAddress(Address address);

    // Selection
    void selectLine(std::size_t line_index);
    void selectAddress(Address address);
    [[nodiscard]] Address selectedAddress() const;

    // Refresh
    void refresh();

    // Configuration
    [[nodiscard]] DisasmConfig& config() { return config_; }

signals:
    void addressSelected(Address address);
    void functionSelected(FunctionId id);

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;

private:
    // Line generation
    void generateAllLines();
    void generateFunctionLines(const analysis::Function& func);
    DisasmLine makeInstructionLine(const Instruction& instr, ByteSpan bytes);
    DisasmLine makeLabelLine(Address address, const QString& name);
    DisasmLine makeFunctionHeader(const analysis::Function& func);
    DisasmLine makeSectionHeader(const QString& name);
    DisasmLine makeAlignmentLine(Address address, Size size);
    QString formatXRefComment(Address address) const;

    // Rendering helpers
    void updateScrollBars();
    int lineHeight() const;
    int addressColumnWidth() const;
    int bytesColumnWidth() const;
    int arrowColumnWidth() const;
    std::size_t lineAtPosition(int y) const;
    void ensureVisible(std::size_t line);

    // Flow arrows
    void calculateFlowArrows();
    void paintFlowArrows(QPainter& painter, int first_visible, int last_visible);

    MainWindow* window_;
    DisasmConfig config_;
    disasm::Decoder decoder_;
    WidgetSymbolResolver symbol_resolver_;
    iced_x86::IntelFormatter formatter_;
    QFont mono_font_;

    // Lines
    std::vector<DisasmLine> lines_;
    std::unordered_map<Address, std::size_t> address_to_line_;

    // Selection
    std::size_t selected_line_{0};
    Address selected_address_{INVALID_ADDRESS};
    std::optional<Address> goto_address_;

    // Cached data
    std::unordered_set<Address> call_targets_;
    std::unordered_set<Address> jump_targets_;

    // Flow arrows
    std::vector<FlowArrow> flow_arrows_;
};

} // namespace picanha::ui
