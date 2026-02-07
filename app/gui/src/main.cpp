// Picanha GUI - ImGUI Application

#include <picanha/ui/app.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <filesystem>
#include <iostream>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#endif

namespace fs = std::filesystem;

void setup_logging() {
    try {
        // Console sink
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        console_sink->set_pattern("[%^%l%$] %v");

        // File sink (optional)
        std::string log_path = "picanha.log";
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_path, true);
        file_sink->set_level(spdlog::level::debug);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");

        // Combined logger
        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        auto logger = std::make_shared<spdlog::logger>("picanha", sinks.begin(), sinks.end());
        logger->set_level(spdlog::level::debug);

        spdlog::set_default_logger(logger);
        spdlog::info("Logging initialized");
    } catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
    }
}

int run_application(int argc, char** argv) {
    setup_logging();

    spdlog::info("Picanha Disassembler starting...");

    // Parse command line for optional file to open
    std::string binary_path;
    std::string project_path;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            std::cout << "Picanha Disassembler GUI\n\n";
            std::cout << "Usage: picanha-gui [OPTIONS] [FILE]\n\n";
            std::cout << "Options:\n";
            std::cout << "  -h, --help     Show this help message\n";
            std::cout << "  -p, --project  Open a project file (.pdb)\n";
            std::cout << "  FILE           Binary file to analyze\n";
            return 0;
        } else if (arg == "--project" || arg == "-p") {
            if (i + 1 < argc) {
                project_path = argv[++i];
            }
        } else if (arg[0] != '-') {
            binary_path = arg;
        }
    }

    // Configure application
    picanha::ui::AppConfig config;
    config.title = "Picanha Disassembler";
    config.window_width = 1600;
    config.window_height = 900;
    config.dark_theme = true;
    config.font_size = 14.0f;

    // Create and initialize application
    picanha::ui::Application app(config);

    if (!app.initialize()) {
        spdlog::error("Failed to initialize application");
        return 1;
    }

    // Open project or binary if specified
    if (!project_path.empty()) {
        if (!app.open_project(project_path)) {
            spdlog::error("Failed to open project: {}", project_path);
        }
    } else if (!binary_path.empty()) {
        if (!app.load_binary(binary_path)) {
            spdlog::error("Failed to load binary: {}", binary_path);
        }
    }

    // Run main loop
    spdlog::info("Entering main loop");
    app.run();

    spdlog::info("Application shutting down");
    return 0;
}

#ifdef _WIN32
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nShowCmd;

    // Get command line arguments
    int argc;
    LPWSTR* argv_wide = CommandLineToArgvW(GetCommandLineW(), &argc);

    // Convert to char**
    std::vector<std::string> args(argc);
    std::vector<char*> argv(argc);
    for (int i = 0; i < argc; ++i) {
        int size = WideCharToMultiByte(CP_UTF8, 0, argv_wide[i], -1, nullptr, 0, nullptr, nullptr);
        args[i].resize(size);
        WideCharToMultiByte(CP_UTF8, 0, argv_wide[i], -1, args[i].data(), size, nullptr, nullptr);
        argv[i] = args[i].data();
    }
    LocalFree(argv_wide);

    return run_application(argc, argv.data());
}
#else
int main(int argc, char* argv[]) {
    return run_application(argc, argv);
}
#endif
