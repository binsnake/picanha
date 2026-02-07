#include <picanha/ui-qt/main_window.hpp>

#include <QApplication>
#include <QStyleFactory>
#include <QSurfaceFormat>
#include <QCommandLineParser>

#ifdef _WIN32
#include <Windows.h>
#endif

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Enable console output on Windows if needed
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }
#endif

    // Enable high DPI scaling
    QApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);

    QApplication app(argc, argv);

    // Application metadata
    QCoreApplication::setOrganizationName("Picanha");
    QCoreApplication::setApplicationName("Picanha Disassembler");
    QCoreApplication::setApplicationVersion("0.1.0");

    // Use Fusion style for consistent cross-platform look
    app.setStyle(QStyleFactory::create("Fusion"));

    // Dark palette
    QPalette darkPalette;
    darkPalette.setColor(QPalette::Window, QColor(30, 30, 30));
    darkPalette.setColor(QPalette::WindowText, QColor(212, 212, 212));
    darkPalette.setColor(QPalette::Base, QColor(30, 30, 30));
    darkPalette.setColor(QPalette::AlternateBase, QColor(45, 45, 45));
    darkPalette.setColor(QPalette::ToolTipBase, QColor(45, 45, 45));
    darkPalette.setColor(QPalette::ToolTipText, QColor(212, 212, 212));
    darkPalette.setColor(QPalette::Text, QColor(212, 212, 212));
    darkPalette.setColor(QPalette::Button, QColor(45, 45, 45));
    darkPalette.setColor(QPalette::ButtonText, QColor(212, 212, 212));
    darkPalette.setColor(QPalette::BrightText, Qt::red);
    darkPalette.setColor(QPalette::Link, QColor(86, 156, 214));
    darkPalette.setColor(QPalette::Highlight, QColor(38, 79, 120));
    darkPalette.setColor(QPalette::HighlightedText, QColor(212, 212, 212));
    darkPalette.setColor(QPalette::Disabled, QPalette::Text, QColor(128, 128, 128));
    darkPalette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(128, 128, 128));
    app.setPalette(darkPalette);

    // Command line parsing
    QCommandLineParser parser;
    parser.setApplicationDescription("Picanha Disassembler - x86_64 PE/COFF binary analysis tool");
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addPositionalArgument("file", "Binary file to open");

    parser.process(app);

    // Create main window
    picanha::ui::MainWindow window;
    window.show();

    // Open file if provided
    const QStringList args = parser.positionalArguments();
    if (!args.isEmpty()) {
        window.loadBinary(args.first());
    }

    return app.exec();
}
