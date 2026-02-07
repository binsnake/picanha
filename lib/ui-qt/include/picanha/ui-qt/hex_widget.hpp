#pragma once

#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>

#include <QAbstractScrollArea>
#include <QFont>
#include <QColor>

#include <vector>
#include <optional>

namespace picanha::ui {

class MainWindow;

// Hex view configuration
struct HexConfig {
    int bytes_per_row{16};
    bool show_ascii{true};
    bool uppercase_hex{false};

    // Colors
    QColor color_background{0x1e, 0x1e, 0x1e};
    QColor color_text{0xd4, 0xd4, 0xd4};
    QColor color_address{0x80, 0x80, 0x80};
    QColor color_hex{0xd4, 0xd4, 0xd4};
    QColor color_ascii{0x6a, 0x99, 0x55};
    QColor color_non_printable{0x60, 0x60, 0x60};
    QColor color_selection{0x26, 0x4f, 0x78};
    QColor color_current_line{0x2d, 0x2d, 0x2d};
    QColor color_separator{0x40, 0x40, 0x40};
};

// Hex view widget
class HexWidget : public QAbstractScrollArea {
    Q_OBJECT

public:
    explicit HexWidget(MainWindow* window, QWidget* parent = nullptr);
    ~HexWidget() override;

    // Navigation
    void gotoAddress(Address address);
    void scrollToAddress(Address address);

    // Selection
    void selectRange(Address start, Address end);
    [[nodiscard]] Address selectionStart() const { return selection_start_; }
    [[nodiscard]] Address selectionEnd() const { return selection_end_; }

    // Refresh
    void refresh();

    // Configuration
    [[nodiscard]] HexConfig& config() { return config_; }

signals:
    void addressSelected(Address address);

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;

private:
    // Helpers
    void updateScrollBars();
    int lineHeight() const;
    int addressColumnWidth() const;
    int hexColumnWidth() const;
    int asciiColumnWidth() const;
    Address addressAtPosition(const QPoint& pos) const;
    int rowAtY(int y) const;
    int byteAtX(int x) const;
    void ensureVisible(Address address);

    MainWindow* window_;
    HexConfig config_;
    QFont mono_font_;

    // Data range
    Address data_start_{0};
    Address data_end_{0};
    std::vector<std::uint8_t> data_cache_;

    // Selection
    Address selection_start_{INVALID_ADDRESS};
    Address selection_end_{INVALID_ADDRESS};
    bool selecting_{false};

    // Current position
    Address current_address_{0};
};

} // namespace picanha::ui
