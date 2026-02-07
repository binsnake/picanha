#include <picanha/ui/app.hpp>
#include <picanha/ui/disasm_view.hpp>
#include <picanha/ui/hex_view.hpp>
#include <picanha/ui/function_list.hpp>
#include <picanha/ui/symbol_list.hpp>
#include <picanha/ui/imports_view.hpp>
#include <picanha/ui/xref_list.hpp>
#include <picanha/loader/binary.hpp>
#include <picanha/loader/pe/pe_parser.hpp>
#include <spdlog/spdlog.h>

#ifdef PICANHA_ENABLE_LLVM
#include <picanha/ui/ir_view.hpp>
#include <picanha/ui/optimized_view.hpp>
#include <picanha/ui/decompiled_view.hpp>
#include <picanha/lift/lifting_service.hpp>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commdlg.h>
#endif

#include <GLFW/glfw3.h>
#ifdef _WIN32
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>
#endif
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <imgui_internal.h>

#include <iced_x86/iced_x86.hpp>
#include <picanha/core/parallel.hpp>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <format>
#include <unordered_map>
#include <unordered_set>

namespace picanha::ui {

namespace {
    Application* g_app = nullptr;
}

Application* get_app() { return g_app; }
void set_app(Application* app) { g_app = app; }

Application::Application(const AppConfig& config)
    : config_(config)
{
    set_app(this);
}

Application::~Application() {
    shutdown();
    if (g_app == this) {
        set_app(nullptr);
    }
}

bool Application::initialize() {
    // Initialize GLFW
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        spdlog::error("Failed to initialize GLFW");
        return false;
    }

    // GL 3.3 + GLSL 330
    const char* glsl_version = "#version 330";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_SCALE_TO_MONITOR, GLFW_TRUE);

    // Get primary monitor DPI scale
    GLFWmonitor* monitor = glfwGetPrimaryMonitor();
    float xscale = 1.0f, yscale = 1.0f;
    if (monitor) {
        glfwGetMonitorContentScale(monitor, &xscale, &yscale);
    }
    dpi_scale_ = xscale;

    // Create window with scaled size
    window_ = glfwCreateWindow(
        static_cast<int>(config_.window_width * dpi_scale_),
        static_cast<int>(config_.window_height * dpi_scale_),
        config_.title.c_str(),
        nullptr,
        nullptr
    );
    if (!window_) {
        spdlog::error("Failed to create GLFW window");
        glfwTerminate();
        return false;
    }

    glfwMakeContextCurrent(window_);
    glfwSwapInterval(config_.vsync ? 1 : 0);
    glfwMaximizeWindow(window_);  // Start maximized

    // Setup callbacks
    glfwSetWindowUserPointer(window_, this);
    glfwSetKeyCallback(window_, glfw_key_callback);
    glfwSetDropCallback(window_, glfw_drop_callback);

    // Setup ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    // ViewportsEnable removed - causes extra window for status bar

    // Setup theme and fonts (with DPI scaling)
    setup_theme();
    setup_fonts();

    // Setup platform/renderer backends
    ImGui_ImplGlfw_InitForOpenGL(window_, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Apply DPI scaling to ImGui style
    ImGui::GetStyle().ScaleAllSizes(dpi_scale_);

    // Create views
    disasm_view_ = std::make_unique<DisasmView>(this);
    hex_view_ = std::make_unique<HexView>(this);
    function_list_ = std::make_unique<FunctionList>(this);
    symbol_list_ = std::make_unique<SymbolList>(this);
    imports_view_ = std::make_unique<ImportsView>(this);
    xref_list_ = std::make_unique<XRefList>(this);

#ifdef PICANHA_ENABLE_LLVM
    ir_view_ = std::make_unique<IRView>(this);
    optimized_view_ = std::make_unique<OptimizedView>(this);
    decompiled_view_ = std::make_unique<DecompiledView>(this);
#endif

    // Setup callbacks
    function_list_->set_selection_callback([this](FunctionId id) {
        navigate_to_function(id);
    });
    symbol_list_->set_selection_callback([this](Address addr) {
        navigate_to(addr);
    });
    xref_list_->set_navigate_callback([this](Address addr) {
        navigate_to(addr);
    });

    log("Picanha Disassembler initialized");
    return true;
}

void Application::shutdown() {
    // Cleanup views
    disasm_view_.reset();
    hex_view_.reset();
    function_list_.reset();
    symbol_list_.reset();
    imports_view_.reset();
    xref_list_.reset();

#ifdef PICANHA_ENABLE_LLVM
    ir_view_.reset();
    optimized_view_.reset();
    decompiled_view_.reset();
    lifting_service_.reset();
#endif

    // Cleanup ImGui
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    // Cleanup GLFW
    if (window_) {
        glfwDestroyWindow(window_);
        window_ = nullptr;
    }
    glfwTerminate();
}

void Application::run() {
    while (!should_close()) {
        begin_frame();
        render_ui();
        end_frame();
    }
}

bool Application::should_close() const {
    return window_ && glfwWindowShouldClose(window_);
}

void Application::request_close() {
    if (window_) {
        glfwSetWindowShouldClose(window_, GLFW_TRUE);
    }
}

bool Application::new_project(const std::string& path, const std::string& name) {
    try {
        project_ = std::make_unique<persistence::Project>();
        if (!project_->create(path, name)) {
            log_error(std::format("Failed to create project: {}", path));
            project_.reset();
            return false;
        }
        log(std::format("Created project: {}", name));
        return true;
    } catch (const std::exception& e) {
        log_error(std::format("Failed to create project: {}", e.what()));
        return false;
    }
}

bool Application::open_project(const std::string& path) {
    try {
        auto proj = std::make_unique<persistence::Project>();
        if (!proj->open(path)) {
            log_error(std::format("Failed to open project: {}", path));
            return false;
        }

        // Load data from project
        project_ = std::move(proj);

        // Load functions
        auto funcs_result = project_->load_functions();
        if (funcs_result) {
            functions_ = std::move(*funcs_result);
        }

        // Load symbols
        auto syms_result = project_->load_symbols(symbols_);
        (void)syms_result; // Ignore error for now

        // Load xrefs
        auto xrefs_result = project_->load_xrefs(xrefs_);
        (void)xrefs_result; // Ignore error for now

        // Refresh views
        function_list_->refresh();
        symbol_list_->refresh();

        log(std::format("Opened project: {}", path));
        return true;
    } catch (const std::exception& e) {
        log_error(std::format("Failed to open project: {}", e.what()));
        return false;
    }
}

bool Application::save_project() {
    if (!project_) {
        log_error("No project open");
        return false;
    }

    try {
        auto funcs_result = project_->save_functions(functions_);
        (void)funcs_result;

        auto syms_result = project_->save_symbols(symbols_);
        (void)syms_result;

        auto xrefs_result = project_->save_xrefs(xrefs_);
        (void)xrefs_result;

        log("Project saved");
        return true;
    } catch (const std::exception& e) {
        log_error(std::format("Failed to save project: {}", e.what()));
        return false;
    }
}

bool Application::close_project() {
    if (project_) {
        save_project();
        project_.reset();
        binary_.reset();
        functions_.clear();
        symbols_.clear();
        xrefs_.clear();

        function_list_->refresh();
        symbol_list_->refresh();

        log("Project closed");
    }
    return true;
}

bool Application::load_binary(const std::string& path) {
    try {
        auto result = loader::Binary::load_file(path);
        if (!result) {
            log_error(std::format("Failed to load binary: {}", result.error().message()));
            return false;
        }
        binary_ = std::move(*result);

        // Update views
        if (hex_view_) {
            auto range = binary_->address_range();
            Size size = range.end - range.start;
            hex_view_->set_view_range(range.start, size);
        }

        auto range = binary_->address_range();
        Size image_size = range.end - range.start;

        log(std::format("Loaded binary: {}", path));
        log(std::format("  Image base: 0x{:016X}", binary_->image_base()));
        log(std::format("  Image size: 0x{:X}", image_size));
        log(std::format("  Entry point: 0x{:016X}", binary_->entry_point()));

        // Navigate to entry point
        if (binary_->entry_point() != INVALID_ADDRESS) {
            navigate_to(binary_->entry_point());
        }

#ifdef PICANHA_ENABLE_LLVM
        // Initialize lifting service
        lifting_service_ = std::make_unique<::picanha::lift::LiftingService>(binary_);
        if (lifting_service_->initialize()) {
            log("Lifting service initialized");
        } else {
            log_warning("Failed to initialize lifting service: " +
                        lifting_service_->error_message());
        }
#endif

        return true;
    } catch (const std::exception& e) {
        log_error(std::format("Failed to load binary: {}", e.what()));
        return false;
    }
}

void Application::navigate_to(Address address) {
    if (address == INVALID_ADDRESS) return;
    if (address == state_.current_address) return;  // Already there

    // If we're in the middle of history, truncate forward entries
    if (state_.nav_position + 1 < state_.nav_history.size()) {
        state_.nav_history.resize(state_.nav_position + 1);
    }

    // Add the NEW address to history
    state_.nav_history.push_back({address, ""});
    state_.nav_position = state_.nav_history.size() - 1;
    state_.current_address = address;

    // Update views
    if (disasm_view_) {
        disasm_view_->goto_address(address);
    }
    if (hex_view_) {
        hex_view_->goto_address(address);
    }
    if (xref_list_) {
        xref_list_->set_target(address);
    }

    // Find containing function
    for (const auto& func : functions_) {
        if (address >= func.start_address() && address < func.start_address() + func.size()) {
            state_.current_function = func.id();
            break;
        }
    }
}

void Application::navigate_to_function(FunctionId id) {
    for (const auto& func : functions_) {
        if (func.id() == id) {
            state_.current_function = id;
            navigate_to(func.start_address());
            break;
        }
    }
}

void Application::navigate_back() {
    if (!can_navigate_back()) return;

    state_.nav_position--;
    Address addr = state_.nav_history[state_.nav_position].address;
    state_.current_address = addr;

    // Update views without adding to history
    if (disasm_view_) {
        disasm_view_->goto_address(addr);
    }
    if (hex_view_) {
        hex_view_->goto_address(addr);
    }

    // Find containing function
    for (const auto& func : functions_) {
        if (addr >= func.start_address() && addr < func.start_address() + func.size()) {
            state_.current_function = func.id();
            break;
        }
    }
}

void Application::navigate_forward() {
    if (!can_navigate_forward()) return;

    state_.nav_position++;
    Address addr = state_.nav_history[state_.nav_position].address;
    state_.current_address = addr;

    // Update views without adding to history
    if (disasm_view_) {
        disasm_view_->goto_address(addr);
    }
    if (hex_view_) {
        hex_view_->goto_address(addr);
    }

    // Find containing function
    for (const auto& func : functions_) {
        if (addr >= func.start_address() && addr < func.start_address() + func.size()) {
            state_.current_function = func.id();
            break;
        }
    }
}

bool Application::can_navigate_back() const {
    return state_.nav_position > 0 && !state_.nav_history.empty();
}

bool Application::can_navigate_forward() const {
    return !state_.nav_history.empty() && state_.nav_position + 1 < state_.nav_history.size();
}

void Application::select_address(Address addr) {
    state_.current_address = addr;
    if (disasm_view_) {
        disasm_view_->select_address(addr);
    }
    if (hex_view_) {
        hex_view_->select_byte(addr);
    }
    if (xref_list_) {
        xref_list_->set_target(addr, XRefMode::ToAddress);
    }
}

void Application::select_function(FunctionId id) {
    state_.current_function = id;
    if (function_list_) {
        function_list_->select_function(id);
    }
}

void Application::run_analysis() {
    if (!binary_) {
        log_error("No binary loaded");
        return;
    }

    // Check if analysis is already running
    if (state_.analysis_running) {
        log_warning("Analysis already in progress");
        return;
    }

    state_.analysis_running = true;
    state_.analysis_progress = 0.0f;
    analysis_progress_atomic_ = 0.0f;
    analysis_complete_ = false;
    state_.analysis_status = "Starting analysis...";
    log("Analysis started (background)");

    // Launch analysis on background thread
    analysis_future_ = std::async(std::launch::async, [this]() {
        run_analysis_background();
    });
}

void Application::run_analysis_background() {
    // Work with a results struct, then transfer pointer to main thread
    auto results = std::make_unique<AnalysisResults>();

    auto add_log = [&results](const std::string& msg) {
        results->logs.push_back(msg);
    };

    FunctionId next_id = 1;

    // Build symbol table from binary (imports, exports)
    results->symbols.build_from_binary(binary_);
    add_log(std::format("Loaded {} symbols ({} imports, {} exports)",
        results->symbols.count(), results->symbols.count_imports(), results->symbols.count_exports()));
    analysis_progress_atomic_ = 0.1f;

    // Collect functions from exception directory (most reliable for x64)
    if (auto* exceptions = binary_->exceptions()) {
        add_log(std::format("Found {} functions in exception directory", exceptions->functions.size()));

        for (const auto& fe : exceptions->functions) {
            analysis::Function func(next_id++, fe.begin_address);

            // Try to get name from exports
            if (auto name = binary_->get_symbol_name(fe.begin_address)) {
                func.set_name(*name);
            } else {
                func.set_name(std::format("sub_{:X}", fe.begin_address));
            }

            func.set_calling_convention(analysis::CallingConvention::Win64);

            // Check if it's an export
            if (binary_->find_export_at(fe.begin_address)) {
                func.set_type(analysis::FunctionType::Export);
            }

            // Create a simple CFG with one block to establish function bounds
            analysis::CFG cfg;
            auto& block = cfg.create_block(fe.begin_address);
            block.set_end_address(fe.end_address);
            cfg.set_entry_block(block.id());
            func.set_cfg(std::move(cfg));

            results->functions.push_back(std::move(func));
        }
        analysis_progress_atomic_ = 0.3f;
    }

    // Add exports that aren't already in the function list
    if (auto* exports = binary_->exports()) {
        for (const auto& exp : exports->exports) {
            if (exp.is_forwarded) continue;

            // Check if we already have this function
            bool found = false;
            for (const auto& f : results->functions) {
                if (f.entry_address() == exp.address) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                analysis::Function func(next_id++, exp.address);
                func.set_name(exp.name.empty() ? std::format("ord_{}", exp.ordinal) : exp.name);
                func.set_type(analysis::FunctionType::Export);
                func.set_calling_convention(analysis::CallingConvention::Win64);
                results->functions.push_back(std::move(func));
            }
        }
        analysis_progress_atomic_ = 0.4f;
    }

    // Sort functions by address
    std::sort(results->functions.begin(), results->functions.end(), [](const auto& a, const auto& b) {
        return a.entry_address() < b.entry_address();
    });
    add_log(std::format("Found {} functions", results->functions.size()));

    // Build xrefs by scanning for call/jump instructions (parallelized with TBB)
    std::atomic<std::size_t> xref_count{0};
    std::atomic<std::size_t> processed_count{0};
    std::size_t func_count = results->functions.size();

    // Thread-local storage for xrefs to avoid contention
    ThreadLocal<std::vector<analysis::XRef>> local_xrefs;

    // Thread-local storage for warnings (log messages)
    ThreadLocal<std::vector<std::string>> local_warnings;

    // Capture binary pointer for lambda (read-only, thread-safe)
    auto binary_ptr = binary_;

    // Parallel xref building
    parallel_for(std::size_t{0}, func_count, [&](std::size_t i) {
        // Check if analysis was stopped
        if (!state_.analysis_running) {
            return;
        }

        const auto& func = results->functions[i];
        Address func_start = func.entry_address();
        Address func_end = func.end_address();

        if (func_end <= func_start) {
            processed_count.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // Safety: limit function size to 1MB to avoid getting stuck on bad data
        Size func_size = func_end - func_start;
        constexpr Size MAX_FUNC_SIZE = 1024 * 1024;
        if (func_size > MAX_FUNC_SIZE) {
            local_warnings.local().push_back(
                std::format("Skipping oversized function at 0x{:X} (size: {})", func_start, func_size));
            processed_count.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // Read function bytes
        auto data = binary_ptr->read(func_start, func_size);
        if (!data) {
            processed_count.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        // Create decoder for this function
        iced_x86::Decoder decoder(64, *data, func_start);

        // Safety: limit instructions per function to prevent infinite loops
        constexpr std::size_t MAX_INSTRUCTIONS = 100000;
        std::size_t instr_count = 0;
        std::size_t local_xref_count = 0;

        // Get thread-local xref vector
        auto& thread_xrefs = local_xrefs.local();

        while (decoder.can_decode() && instr_count < MAX_INSTRUCTIONS) {
            auto result = decoder.decode();
            if (!result) break;

            ++instr_count;
            const auto& instr = *result;
            auto flow = iced_x86::InstructionExtensions::flow_control(instr);
            Address target = INVALID_ADDRESS;

            // Check for direct calls and jumps
            if (flow == iced_x86::FlowControl::CALL ||
                flow == iced_x86::FlowControl::UNCONDITIONAL_BRANCH ||
                flow == iced_x86::FlowControl::CONDITIONAL_BRANCH) {

                // Get target address if it's a near branch
                if (instr.op_count() > 0) {
                    auto op_kind = instr.op_kind(0);
                    if (op_kind == iced_x86::OpKind::NEAR_BRANCH64 ||
                        op_kind == iced_x86::OpKind::NEAR_BRANCH32 ||
                        op_kind == iced_x86::OpKind::NEAR_BRANCH16) {
                        target = instr.near_branch_target();
                    }
                }

                if (target != INVALID_ADDRESS && target != instr.ip()) {
                    analysis::XRefType xref_type = (flow == iced_x86::FlowControl::CALL)
                        ? analysis::XRefType::Call
                        : analysis::XRefType::Jump;

                    // Add to thread-local storage (no contention)
                    analysis::XRef xref;
                    xref.from = instr.ip();
                    xref.to = target;
                    xref.type = xref_type;
                    xref.flow = analysis::XRefFlow::Near;
                    thread_xrefs.push_back(xref);
                    local_xref_count++;
                }
            }
        }

        // Warn if we hit the instruction limit
        if (instr_count >= MAX_INSTRUCTIONS) {
            local_warnings.local().push_back(
                std::format("Warning: Hit instruction limit at function 0x{:X}", func_start));
        }

        // Update counters atomically
        xref_count.fetch_add(local_xref_count, std::memory_order_relaxed);
        auto done = processed_count.fetch_add(1, std::memory_order_relaxed) + 1;

        // Update progress atomically (less frequently to reduce overhead)
        if (done % 50 == 0 || done == func_count) {
            // Progress from 40% to 90% during xref building
            analysis_progress_atomic_ = 0.4f + 0.5f * (static_cast<float>(done) / static_cast<float>(func_count));
        }
    });

    // Merge thread-local xrefs into results (single-threaded merge phase)
    for (auto& thread_xrefs : local_xrefs) {
        for (const auto& xref : thread_xrefs) {
            results->xrefs.add(xref);
        }
    }

    // Collect warnings
    for (auto& warnings : local_warnings) {
        for (const auto& msg : warnings) {
            add_log(msg);
        }
    }

    // Update to 95% after xref building
    analysis_progress_atomic_ = 0.95f;

    add_log(std::format("Analysis complete: {} functions, {} xrefs", results->functions.size(), xref_count.load()));

    // Transfer results pointer to pending storage (O(1) - just moves a pointer)
    {
        std::lock_guard<std::mutex> lock(analysis_mutex_);
        pending_results_ = std::move(results);
    }

    analysis_progress_atomic_ = 1.0f;
    analysis_complete_ = true;
}

void Application::check_analysis_completion() {
    // Update progress from atomic
    state_.analysis_progress = analysis_progress_atomic_.load();

    // Update status based on progress
    if (state_.analysis_running && !analysis_complete_) {
        if (state_.analysis_progress < 0.1f) {
            state_.analysis_status = "Starting analysis...";
        } else if (state_.analysis_progress < 0.3f) {
            state_.analysis_status = "Building symbol table...";
        } else if (state_.analysis_progress < 0.4f) {
            state_.analysis_status = "Parsing exception directory...";
        } else if (state_.analysis_progress < 0.9f) {
            state_.analysis_status = "Building cross-references...";
        } else {
            state_.analysis_status = "Finalizing...";
        }
    }

    // Check if analysis completed
    if (analysis_complete_.exchange(false)) {
        // Transfer results from pending to main storage
        std::unique_ptr<AnalysisResults> results;
        {
            std::lock_guard<std::mutex> lock(analysis_mutex_);
            results = std::move(pending_results_);
        }

        if (results) {
            // Swap data into main storage (efficient move)
            functions_.swap(results->functions);
            symbols_ = std::move(results->symbols);
            xrefs_ = std::move(results->xrefs);

            // Log all pending messages
            for (const auto& msg : results->logs) {
                log(msg);
            }
        }

        state_.analysis_running = false;
        state_.analysis_progress = 1.0f;
        state_.analysis_status = std::format("Found {} functions, {} xrefs",
            functions_.size(), xrefs_.count());

        // Refresh views on main thread
        function_list_->refresh();
        symbol_list_->refresh();
        imports_view_->refresh();

        if (disasm_view_) {
            disasm_view_->refresh();
            log("Disassembly refreshed with symbol resolution");
        }
    }
}

void Application::stop_analysis() {
    state_.analysis_running = false;
    state_.analysis_status = "Analysis stopped";
    log("Analysis stopped");
}

void Application::log(const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &time);

    auto formatted = std::format("[{:02}:{:02}:{:02}] {}",
        tm.tm_hour, tm.tm_min, tm.tm_sec, message);

    log_buffer_.push_back(formatted);
    if (log_buffer_.size() > max_log_entries_) {
        log_buffer_.erase(log_buffer_.begin());
    }

    spdlog::info(message);
}

void Application::log_warning(const std::string& message) {
    log("[WARNING] " + message);
    spdlog::warn(message);
}

void Application::log_error(const std::string& message) {
    log("[ERROR] " + message);
    spdlog::error(message);
}

void Application::begin_frame() {
    glfwPollEvents();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
}

void Application::end_frame() {
    ImGui::Render();

    int display_w, display_h;
    glfwGetFramebufferSize(window_, &display_w, &display_h);
    glViewport(0, 0, display_w, display_h);
    glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);

    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    glfwSwapBuffers(window_);
}

void Application::render_ui() {
    // Check if background analysis completed
    if (state_.analysis_running) {
        check_analysis_completion();
    }

    // Process keyboard shortcuts first (respects ImGui focus)
    process_shortcuts();

    // Calculate toolbar and status bar heights
    float toolbar_height = ImGui::GetFrameHeight() + 8.0f;
    float status_height = ImGui::GetFrameHeight() + 4.0f;

    // Render main menu first
    render_main_menu();

    // Render toolbar (fixed at top of work area)
    render_toolbar();

    // Render dockspace (between toolbar and status bar)
    render_dockspace(toolbar_height, status_height);

    // Render views
    if (state_.show_hex_view && hex_view_) {
        ImGui::Begin("Hex View", &state_.show_hex_view);
        hex_view_->render();
        ImGui::End();
    }

    ImGui::Begin("Disassembly");
    if (disasm_view_) {
        disasm_view_->render();
    }
    ImGui::End();

    if (state_.show_function_list && function_list_) {
        ImGui::Begin("Functions", &state_.show_function_list);
        function_list_->render();
        ImGui::End();
    }

    if (state_.show_symbol_list && symbol_list_) {
        ImGui::Begin("Symbols", &state_.show_symbol_list);
        symbol_list_->render();
        ImGui::End();
    }

    if (state_.show_imports && imports_view_) {
        ImGui::Begin("Imports", &state_.show_imports);
        imports_view_->render();
        ImGui::End();
    }

    if (state_.show_xref_list && xref_list_) {
        ImGui::Begin("Cross-References", &state_.show_xref_list);
        xref_list_->render();
        ImGui::End();
    }

    if (state_.show_output_log) {
        ImGui::Begin("Output", &state_.show_output_log);
        for (const auto& line : log_buffer_) {
            ImGui::TextUnformatted(line.c_str());
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
            ImGui::SetScrollHereY(1.0f);
        }
        ImGui::End();
    }

    if (state_.show_demo_window) {
        ImGui::ShowDemoWindow(&state_.show_demo_window);
    }

#ifdef PICANHA_ENABLE_LLVM
    // Render IR views in a combined window (right split pane)
    if (state_.show_ir_view || state_.show_optimized_view || state_.show_decompiled_view) {
        ImGui::Begin("Lifted IR", nullptr);

        if (ImGui::BeginTabBar("IRTabs")) {
            if (state_.show_ir_view) {
                if (ImGui::BeginTabItem("IR")) {
                    if (ir_view_) ir_view_->render();
                    ImGui::EndTabItem();
                }
            }
            if (state_.show_optimized_view) {
                if (ImGui::BeginTabItem("Optimized")) {
                    if (optimized_view_) optimized_view_->render();
                    ImGui::EndTabItem();
                }
            }
            if (state_.show_decompiled_view) {
                if (ImGui::BeginTabItem("Decompiled")) {
                    if (decompiled_view_) decompiled_view_->render();
                    ImGui::EndTabItem();
                }
            }
            ImGui::EndTabBar();
        }

        ImGui::End();
    }
#endif

    // Render status bar (fixed at bottom)
    render_status_bar();

    // Dialogs
    if (show_open_binary_) show_open_binary_dialog();
    if (show_new_project_) show_new_project_dialog();
    if (show_open_project_) show_open_project_dialog();
    if (show_about_) show_about_dialog();
    if (show_settings_) show_settings_dialog();
    if (show_goto_address_) show_goto_address_dialog();
}

void Application::process_shortcuts() {
    // Don't process if a popup/modal is open
    if (ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopup)) {
        return;
    }

    // Don't process if text input is active (typing in a field)
    if (ImGui::GetIO().WantTextInput) {
        return;
    }

    // Use GLFW directly for reliable key detection
    bool ctrl = glfwGetKey(window_, GLFW_KEY_LEFT_CONTROL) == GLFW_PRESS ||
                glfwGetKey(window_, GLFW_KEY_RIGHT_CONTROL) == GLFW_PRESS;
    bool alt = glfwGetKey(window_, GLFW_KEY_LEFT_ALT) == GLFW_PRESS ||
               glfwGetKey(window_, GLFW_KEY_RIGHT_ALT) == GLFW_PRESS;
    bool shift = glfwGetKey(window_, GLFW_KEY_LEFT_SHIFT) == GLFW_PRESS ||
                 glfwGetKey(window_, GLFW_KEY_RIGHT_SHIFT) == GLFW_PRESS;

    // Track key states to detect press (not hold)
    static std::unordered_set<int> keys_down;

    auto key_just_pressed = [&](int key) -> bool {
        bool is_down = glfwGetKey(window_, key) == GLFW_PRESS;
        bool was_down = keys_down.count(key) > 0;
        if (is_down && !was_down) {
            keys_down.insert(key);
            return true;
        }
        if (!is_down && was_down) {
            keys_down.erase(key);
        }
        return false;
    };

    // Single-key shortcuts (no modifiers)
    if (!ctrl && !alt && !shift) {
        // G - Go to address
        if (key_just_pressed(GLFW_KEY_G)) {
            show_goto_address_ = true;
            std::memset(goto_address_buf_, 0, sizeof(goto_address_buf_));
        }

        // F5 - Run analysis
        if (key_just_pressed(GLFW_KEY_F5)) {
            if (!state_.analysis_running && has_binary()) {
                run_analysis();
            }
        }

        // Escape - Close popups/dialogs
        if (key_just_pressed(GLFW_KEY_ESCAPE)) {
            show_goto_address_ = false;
            show_about_ = false;
            show_settings_ = false;
        }

#ifdef PICANHA_ENABLE_LLVM
        // L - Lift current function
        if (key_just_pressed(GLFW_KEY_L)) {
            lift_current_function();
        }

        // D - Decompile current function
        if (key_just_pressed(GLFW_KEY_D)) {
            decompile_current_function();
        }
#endif
    }

    // Ctrl+key shortcuts
    if (ctrl && !alt) {
        // Ctrl+G - Go to address (alternative)
        if (key_just_pressed(GLFW_KEY_G)) {
            show_goto_address_ = true;
            std::memset(goto_address_buf_, 0, sizeof(goto_address_buf_));
        }

        // Ctrl+N - New project
        if (key_just_pressed(GLFW_KEY_N)) {
            show_new_project_ = true;
        }

        // Ctrl+O - Open project
        if (!shift && key_just_pressed(GLFW_KEY_O)) {
            show_open_project_ = true;
        }

        // Ctrl+Shift+O - Open binary
        if (shift && key_just_pressed(GLFW_KEY_O)) {
            show_open_binary_ = true;
        }

        // Ctrl+S - Save project
        if (key_just_pressed(GLFW_KEY_S)) {
            save_project();
        }
    }

    // Alt+key shortcuts
    if (alt && !ctrl) {
        // Alt+Left - Navigate back
        if (key_just_pressed(GLFW_KEY_LEFT)) {
            navigate_back();
        }

        // Alt+Right - Navigate forward
        if (key_just_pressed(GLFW_KEY_RIGHT)) {
            navigate_forward();
        }
    }

    // Update key states for keys not checked above (cleanup)
    // This ensures keys that are released get removed from the set
    for (auto it = keys_down.begin(); it != keys_down.end(); ) {
        if (glfwGetKey(window_, *it) != GLFW_PRESS) {
            it = keys_down.erase(it);
        } else {
            ++it;
        }
    }
}

void Application::show_goto_address_dialog() {
    // Track if we just opened the popup
    static bool popup_just_opened = true;

    if (!ImGui::IsPopupOpen("Go to Address")) {
        ImGui::OpenPopup("Go to Address");
        popup_just_opened = true;
    }

    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Go to Address", &show_goto_address_, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Enter address (hex):");

        // Focus the input field on first appearance
        if (popup_just_opened) {
            ImGui::SetKeyboardFocusHere();
            popup_just_opened = false;
        }

        bool enter_pressed = ImGui::InputText("##address", goto_address_buf_, sizeof(goto_address_buf_),
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);

        if (enter_pressed || ImGui::Button("Go", ImVec2(80, 0))) {
            // Parse the address
            char* end = nullptr;
            Address addr = std::strtoull(goto_address_buf_, &end, 16);
            if (end != goto_address_buf_ && addr != 0) {
                navigate_to(addr);
                show_goto_address_ = false;
                popup_just_opened = true;
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(80, 0))) {
            show_goto_address_ = false;
            popup_just_opened = true;
        }

        // Also close on Escape
        if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
            show_goto_address_ = false;
            popup_just_opened = true;
        }

        ImGui::EndPopup();
    }
}

void Application::render_main_menu() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("New Project...", "Ctrl+N")) {
                show_new_project_ = true;
            }
            if (ImGui::MenuItem("Open Project...", "Ctrl+O")) {
                show_open_project_ = true;
            }
            if (ImGui::MenuItem("Save Project", "Ctrl+S", false, has_project())) {
                save_project();
            }
            if (ImGui::MenuItem("Close Project", nullptr, false, has_project())) {
                close_project();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Open Binary...", "Ctrl+Shift+O")) {
                show_open_binary_ = true;
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) {
                request_close();
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Edit")) {
            if (ImGui::MenuItem("Undo", "Ctrl+Z", false, false)) {}
            if (ImGui::MenuItem("Redo", "Ctrl+Y", false, false)) {}
            ImGui::Separator();
            if (ImGui::MenuItem("Settings...", nullptr)) {
                show_settings_ = true;
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Hex View", nullptr, &state_.show_hex_view);
            ImGui::MenuItem("Functions", nullptr, &state_.show_function_list);
            ImGui::MenuItem("Symbols", nullptr, &state_.show_symbol_list);
            ImGui::MenuItem("Imports", nullptr, &state_.show_imports);
            ImGui::MenuItem("Cross-References", nullptr, &state_.show_xref_list);
            ImGui::MenuItem("Output Log", nullptr, &state_.show_output_log);
#ifdef PICANHA_ENABLE_LLVM
            ImGui::Separator();
            ImGui::MenuItem("LLVM IR", nullptr, &state_.show_ir_view);
            ImGui::MenuItem("Optimized IR", nullptr, &state_.show_optimized_view);
            ImGui::MenuItem("Decompiled", nullptr, &state_.show_decompiled_view);
#endif
            ImGui::Separator();
            ImGui::MenuItem("ImGui Demo", nullptr, &state_.show_demo_window);
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Navigate")) {
            if (ImGui::MenuItem("Go to Address...", "G")) {
                show_goto_address_ = true;
                std::memset(goto_address_buf_, 0, sizeof(goto_address_buf_));
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Back", "Alt+Left", false, can_navigate_back())) {
                navigate_back();
            }
            if (ImGui::MenuItem("Forward", "Alt+Right", false, can_navigate_forward())) {
                navigate_forward();
            }
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Analysis")) {
            if (ImGui::MenuItem("Run Analysis", "F5", false, has_binary() && !state_.analysis_running)) {
                run_analysis();
            }
            if (ImGui::MenuItem("Stop Analysis", nullptr, false, state_.analysis_running)) {
                stop_analysis();
            }
#ifdef PICANHA_ENABLE_LLVM
            ImGui::Separator();
            if (ImGui::MenuItem("Lift to IR", "L", false, has_binary() && has_lifting_service())) {
                lift_current_function();
            }
            if (ImGui::MenuItem("Decompile", "D", false, has_binary() && has_lifting_service())) {
                decompile_current_function();
            }
#endif
            ImGui::EndMenu();
        }

        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("About...")) {
                show_about_ = true;
            }
            ImGui::EndMenu();
        }

        ImGui::EndMainMenuBar();
    }
}

void Application::render_toolbar() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    float toolbar_height = ImGui::GetFrameHeight() + 8.0f;

    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x, viewport->WorkPos.y));
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x, toolbar_height));

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4, 4));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 4));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

    ImGuiWindowFlags toolbar_flags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoMove;
    if (ImGui::Begin("##Toolbar", nullptr, toolbar_flags)) {
        if (ImGui::Button("Open")) {
            show_open_binary_ = true;
        }
        ImGui::SameLine();

        ImGui::BeginDisabled(!has_project());
        if (ImGui::Button("Save")) {
            save_project();
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        ImGui::Text("|");
        ImGui::SameLine();

        ImGui::BeginDisabled(!can_navigate_back());
        if (ImGui::Button("<")) {
            navigate_back();
        }
        ImGui::EndDisabled();

        ImGui::SameLine();

        ImGui::BeginDisabled(!can_navigate_forward());
        if (ImGui::Button(">")) {
            navigate_forward();
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        ImGui::Text("|");
        ImGui::SameLine();

        ImGui::BeginDisabled(!has_binary() || state_.analysis_running);
        if (ImGui::Button("Analyze")) {
            run_analysis();
        }
        ImGui::EndDisabled();

        if (state_.analysis_running) {
            ImGui::SameLine();
            ImGui::ProgressBar(state_.analysis_progress, ImVec2(200, 0));
        }

        ImGui::End();
    }

    ImGui::PopStyleVar(3);
}

void Application::render_status_bar() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    float status_height = ImGui::GetFrameHeight() + 4.0f;

    // Position at bottom of window (use Pos, not WorkPos to go below dockspace)
    ImGui::SetNextWindowPos(ImVec2(viewport->Pos.x, viewport->Pos.y + viewport->Size.y - status_height));
    ImGui::SetNextWindowSize(ImVec2(viewport->Size.x, status_height));

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(8, 2));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

    ImGuiWindowFlags status_flags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus;
    if (ImGui::Begin("##StatusBar", nullptr, status_flags)) {
        if (state_.current_address != INVALID_ADDRESS) {
            ImGui::Text("Address: 0x%016llX", state_.current_address);
        } else {
            ImGui::Text("No address selected");
        }

        ImGui::SameLine(ImGui::GetWindowWidth() - 250);
        ImGui::Text("%s", state_.analysis_status.c_str());

        ImGui::End();
    }

    ImGui::PopStyleVar(2);
}

void Application::render_dockspace(float toolbar_height, float status_height) {
    ImGuiViewport* viewport = ImGui::GetMainViewport();

    // Position dockspace below toolbar and above status bar
    ImVec2 dockspace_pos(viewport->WorkPos.x, viewport->WorkPos.y + toolbar_height);
    ImVec2 dockspace_size(viewport->WorkSize.x, viewport->WorkSize.y - toolbar_height - status_height);

    ImGui::SetNextWindowPos(dockspace_pos);
    ImGui::SetNextWindowSize(dockspace_size);
    ImGui::SetNextWindowViewport(viewport->ID);

    ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoDocking |
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

    ImGui::Begin("DockSpace", nullptr, window_flags);
    ImGui::PopStyleVar(3);

    ImGuiID dockspace_id = ImGui::GetID("MainDockSpace");

    // Set up initial dock layout on first run (IDA-style)
    static bool first_time = true;
    if (first_time) {
        first_time = false;

        ImGui::DockBuilderRemoveNode(dockspace_id);
        ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(dockspace_id, dockspace_size);

        // IDA-style layout:
        // [Functions] [  Tabbed: Disassembly | Hex View | Symbols | Imports | XRefs  ]
        // [         Output                                                           ]

        ImGuiID dock_main = dockspace_id;
        ImGuiID dock_bottom = ImGui::DockBuilderSplitNode(dock_main, ImGuiDir_Down, 0.20f, nullptr, &dock_main);
        ImGuiID dock_left = ImGui::DockBuilderSplitNode(dock_main, ImGuiDir_Left, 0.15f, nullptr, &dock_main);

        // Dock windows - main area gets tabbed views like IDA
        ImGui::DockBuilderDockWindow("Functions", dock_left);
        ImGui::DockBuilderDockWindow("Disassembly", dock_main);
        ImGui::DockBuilderDockWindow("Hex View", dock_main);      // Tabbed with Disassembly
        ImGui::DockBuilderDockWindow("Symbols", dock_main);       // Tabbed with Disassembly
        ImGui::DockBuilderDockWindow("Imports", dock_main);       // Tabbed with Disassembly
        ImGui::DockBuilderDockWindow("Cross-References", dock_main);  // Tabbed with Disassembly
        ImGui::DockBuilderDockWindow("Output", dock_bottom);

        ImGui::DockBuilderFinish(dockspace_id);
    }

    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_PassthruCentralNode);

    ImGui::End();
}

void Application::show_open_binary_dialog() {
#ifdef _WIN32
    // Use native Windows file dialog
    show_open_binary_ = false;

    wchar_t filename[MAX_PATH] = {0};

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = glfwGetWin32Window(window_);
    ofn.lpstrFilter = L"Executable Files (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Open Binary";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn)) {
        // Convert wide string to UTF-8
        int size = WideCharToMultiByte(CP_UTF8, 0, filename, -1, nullptr, 0, nullptr, nullptr);
        std::string path(size - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, filename, -1, &path[0], size, nullptr, nullptr);
        load_binary(path);
    }
#else
    // Fallback to ImGui dialog on non-Windows
    ImGui::OpenPopup("Open Binary");

    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Open Binary", &show_open_binary_, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Enter path to binary file:");
        ImGui::InputText("##path", &dialog_path_[0], dialog_path_.capacity());

        if (ImGui::Button("Open", ImVec2(120, 0))) {
            if (load_binary(dialog_path_)) {
                show_open_binary_ = false;
                dialog_path_.clear();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            show_open_binary_ = false;
            dialog_path_.clear();
        }

        ImGui::EndPopup();
    }
#endif
}

void Application::show_new_project_dialog() {
#ifdef _WIN32
    // Use native Windows save dialog
    show_new_project_ = false;

    wchar_t filename[MAX_PATH] = L"NewProject.pproj";

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = glfwGetWin32Window(window_);
    ofn.lpstrFilter = L"Picanha Project (*.pproj)\0*.pproj\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Create New Project";
    ofn.lpstrDefExt = L"pproj";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetSaveFileNameW(&ofn)) {
        int size = WideCharToMultiByte(CP_UTF8, 0, filename, -1, nullptr, 0, nullptr, nullptr);
        std::string path(size - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, filename, -1, &path[0], size, nullptr, nullptr);

        // Extract project name from filename
        std::string name = path;
        auto last_slash = name.find_last_of("\\/");
        if (last_slash != std::string::npos) {
            name = name.substr(last_slash + 1);
        }
        auto dot = name.find_last_of('.');
        if (dot != std::string::npos) {
            name = name.substr(0, dot);
        }

        new_project(path, name);
    }
#else
    ImGui::OpenPopup("New Project");

    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("New Project", &show_new_project_, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Project Name:");
        ImGui::InputText("##name", &dialog_name_[0], dialog_name_.capacity());

        ImGui::Text("Project Path:");
        ImGui::InputText("##path", &dialog_path_[0], dialog_path_.capacity());

        if (ImGui::Button("Create", ImVec2(120, 0))) {
            if (new_project(dialog_path_, dialog_name_)) {
                show_new_project_ = false;
                dialog_path_.clear();
                dialog_name_.clear();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            show_new_project_ = false;
            dialog_path_.clear();
            dialog_name_.clear();
        }

        ImGui::EndPopup();
    }
#endif
}

void Application::show_open_project_dialog() {
#ifdef _WIN32
    // Use native Windows file dialog
    show_open_project_ = false;

    wchar_t filename[MAX_PATH] = {0};

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = glfwGetWin32Window(window_);
    ofn.lpstrFilter = L"Picanha Project (*.pproj)\0*.pproj\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = L"Open Project";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn)) {
        int size = WideCharToMultiByte(CP_UTF8, 0, filename, -1, nullptr, 0, nullptr, nullptr);
        std::string path(size - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, filename, -1, &path[0], size, nullptr, nullptr);
        open_project(path);
    }
#else
    ImGui::OpenPopup("Open Project");

    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Open Project", &show_open_project_, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Enter path to project file:");
        ImGui::InputText("##path", &dialog_path_[0], dialog_path_.capacity());

        if (ImGui::Button("Open", ImVec2(120, 0))) {
            if (open_project(dialog_path_)) {
                show_open_project_ = false;
                dialog_path_.clear();
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            show_open_project_ = false;
            dialog_path_.clear();
        }

        ImGui::EndPopup();
    }
#endif
}

void Application::show_about_dialog() {
    ImGui::OpenPopup("About Picanha");

    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("About Picanha", &show_about_, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Picanha Disassembler");
        ImGui::Text("Version 0.1.0");
        ImGui::Separator();
        ImGui::Text("A modern x86_64 disassembler for Windows PE/COFF binaries");
        ImGui::Separator();

        if (ImGui::Button("OK", ImVec2(120, 0))) {
            show_about_ = false;
        }

        ImGui::EndPopup();
    }
}

void Application::show_settings_dialog() {
    ImGui::OpenPopup("Settings");

    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_Appearing);

    if (ImGui::BeginPopupModal("Settings", &show_settings_)) {
        if (ImGui::BeginTabBar("SettingsTabs")) {
            if (ImGui::BeginTabItem("General")) {
                ImGui::Checkbox("VSync", &config_.vsync);
                ImGui::SliderFloat("Font Size", &config_.font_size, 10.0f, 24.0f);
                ImGui::Checkbox("Dark Theme", &config_.dark_theme);
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Disassembly")) {
                if (disasm_view_) {
                    auto& cfg = disasm_view_->config();
                    ImGui::Checkbox("Show Addresses", &cfg.show_addresses);
                    ImGui::Checkbox("Show Bytes", &cfg.show_bytes);
                    ImGui::Checkbox("Show Cross-References", &cfg.show_xrefs);
                    ImGui::Checkbox("Show Comments", &cfg.show_comments);
                    ImGui::Checkbox("Syntax Highlighting", &cfg.syntax_highlight);
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Hex View")) {
                if (hex_view_) {
                    auto& cfg = hex_view_->config();
                    ImGui::SliderInt("Bytes per Row", &cfg.bytes_per_row, 8, 32);
                    ImGui::Checkbox("Show ASCII", &cfg.show_ascii);
                    ImGui::Checkbox("Show Address", &cfg.show_address);
                    ImGui::Checkbox("Uppercase Hex", &cfg.uppercase_hex);
                }
                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }

        ImGui::Separator();
        if (ImGui::Button("Close", ImVec2(120, 0))) {
            show_settings_ = false;
        }

        ImGui::EndPopup();
    }
}

void Application::setup_theme() {
    if (config_.dark_theme) {
        ImGui::StyleColorsDark();
    } else {
        ImGui::StyleColorsLight();
    }

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 4.0f;
    style.FrameRounding = 2.0f;
    style.ScrollbarRounding = 2.0f;
    style.GrabRounding = 2.0f;
    style.TabRounding = 2.0f;

    // Custom dark theme colors
    if (config_.dark_theme) {
        auto& colors = style.Colors;
        colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
        colors[ImGuiCol_Header] = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
        colors[ImGuiCol_HeaderHovered] = ImVec4(0.30f, 0.30f, 0.30f, 1.00f);
        colors[ImGuiCol_HeaderActive] = ImVec4(0.25f, 0.25f, 0.25f, 1.00f);
        colors[ImGuiCol_TitleBg] = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
        colors[ImGuiCol_TitleBgActive] = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
        colors[ImGuiCol_Tab] = ImVec4(0.15f, 0.15f, 0.15f, 1.00f);
        colors[ImGuiCol_TabHovered] = ImVec4(0.30f, 0.30f, 0.30f, 1.00f);
        colors[ImGuiCol_TabSelected] = ImVec4(0.20f, 0.20f, 0.20f, 1.00f);
    }
}

void Application::setup_fonts() {
    ImGuiIO& io = ImGui::GetIO();

    // Scale font size by DPI
    float scaled_font_size = config_.font_size * dpi_scale_;

    ImFontConfig font_cfg;
    font_cfg.OversampleH = 3;
    font_cfg.OversampleV = 3;
    font_cfg.PixelSnapH = true;

    bool font_loaded = false;

    // Try user-specified font first
    if (!config_.font_path.empty()) {
        if (io.Fonts->AddFontFromFileTTF(config_.font_path.c_str(), scaled_font_size, &font_cfg)) {
            font_loaded = true;
        }
    }

#ifdef _WIN32
    // Try Windows system fonts for better rendering
    if (!font_loaded) {
        // Consolas is a good monospace font for code
        const char* font_paths[] = {
            "C:\\Windows\\Fonts\\consola.ttf",   // Consolas
            "C:\\Windows\\Fonts\\segoeui.ttf",   // Segoe UI
            "C:\\Windows\\Fonts\\arial.ttf",     // Arial fallback
        };

        for (const auto* path : font_paths) {
            if (io.Fonts->AddFontFromFileTTF(path, scaled_font_size, &font_cfg)) {
                font_loaded = true;
                spdlog::info("Using font: {}", path);
                break;
            }
        }
    }
#endif

    // Fallback to default font
    if (!font_loaded) {
        font_cfg.SizePixels = scaled_font_size;
        io.Fonts->AddFontDefault(&font_cfg);
    }

    // Set font global scale to 1.0 since we're already using scaled font size
    io.FontGlobalScale = 1.0f;
}

void Application::glfw_error_callback(int error, const char* description) {
    spdlog::error("GLFW Error {}: {}", error, description);
}

void Application::glfw_key_callback(GLFWwindow* window, int key, int scancode, int action, int mods) {
    (void)scancode;

    if (action != GLFW_PRESS && action != GLFW_REPEAT) return;

    auto* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    if (!app) return;

    // Global shortcuts
    if (mods & GLFW_MOD_CONTROL) {
        switch (key) {
            case GLFW_KEY_N:
                app->show_new_project_ = true;
                break;
            case GLFW_KEY_O:
                if (mods & GLFW_MOD_SHIFT) {
                    app->show_open_binary_ = true;
                } else {
                    app->show_open_project_ = true;
                }
                break;
            case GLFW_KEY_S:
                app->save_project();
                break;
            default:
                break;
        }
    }

    if (mods & GLFW_MOD_ALT) {
        switch (key) {
            case GLFW_KEY_LEFT:
                app->navigate_back();
                break;
            case GLFW_KEY_RIGHT:
                app->navigate_forward();
                break;
            default:
                break;
        }
    }

    if (key == GLFW_KEY_F5 && action == GLFW_PRESS) {
        if (!app->state_.analysis_running && app->has_binary()) {
            app->run_analysis();
        }
    }
}

void Application::glfw_drop_callback(GLFWwindow* window, int count, const char** paths) {
    auto* app = static_cast<Application*>(glfwGetWindowUserPointer(window));
    if (!app || count < 1) return;

    // Load the first dropped file as a binary
    app->load_binary(paths[0]);
}

#ifdef PICANHA_ENABLE_LLVM
void Application::lift_current_function() {
    if (state_.current_function != INVALID_FUNCTION_ID) {
        lift_function(state_.current_function);
    } else if (state_.current_address != INVALID_ADDRESS) {
        // Try to lift by address if no function selected
        if (!lifting_service_ || !lifting_service_->is_initialized()) {
            log_error("Lifting service not available");
            return;
        }

        log(std::format("Lifting at address 0x{:X}...", state_.current_address));

        auto result = lifting_service_->lift_address(state_.current_address);
        if (result.success && result.lifted) {
            current_lifted_ = result.lifted;
            if (ir_view_) ir_view_->set_function(current_lifted_);
            if (optimized_view_) optimized_view_->set_function(current_lifted_);
            if (decompiled_view_) decompiled_view_->set_function(current_lifted_);
            state_.show_ir_view = true;
            log("Lifting complete");
        } else {
            log_error("Lifting failed: " + result.error);
        }
    }
}

void Application::lift_function(FunctionId id) {
    if (!lifting_service_ || !lifting_service_->is_initialized()) {
        log_error("Lifting service not available");
        return;
    }

    // Find the function
    auto it = std::find_if(functions_.begin(), functions_.end(),
        [id](const auto& f) { return f.id() == id; });

    if (it == functions_.end()) {
        log_error("Function not found");
        return;
    }

    log(std::format("Lifting function: {}", it->name()));

    auto result = lifting_service_->lift_function(*it);
    if (result.success && result.lifted) {
        current_lifted_ = result.lifted;
        if (ir_view_) ir_view_->set_function(current_lifted_);
        if (optimized_view_) optimized_view_->set_function(current_lifted_);
        if (decompiled_view_) decompiled_view_->set_function(current_lifted_);
        state_.show_ir_view = true;
        log(std::format("Lifting complete: {}", it->name()));
    } else {
        log_error("Lifting failed: " + result.error);
    }
}

void Application::decompile_current_function() {
    if (!lifting_service_ || !lifting_service_->is_initialized()) {
        log_error("Lifting service not available");
        return;
    }

    // First lift the function if not already lifted or if address doesn't match
    if (!current_lifted_ ||
        (current_lifted_->entry_address() != state_.current_address)) {
        // Need to lift first
        lift_current_function();
    }

    // Now set the decompiled view and show it
    if (current_lifted_ && decompiled_view_) {
        decompiled_view_->set_function(current_lifted_);
        state_.show_decompiled_view = true;
        log("Decompilation requested");
    }
}
#endif

} // namespace picanha::ui
