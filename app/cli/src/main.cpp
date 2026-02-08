// Picanha CLI - Command-line interface for the disassembler

#include <picanha/core/types.hpp>
#include <picanha/loader/binary.hpp>
#include <picanha/loader/pe/pe_parser.hpp>
#include <picanha/disasm/decoder.hpp>
#include <picanha/disasm/disassembly_context.hpp>
#include <picanha/analysis/cfg.hpp>
#include <picanha/analysis/cfg_builder.hpp>
#include <picanha/analysis/function.hpp>
#include <picanha/analysis/function_detector.hpp>
#include <picanha/analysis/symbol_table.hpp>
#include <picanha/analysis/xref_manager.hpp>
#include <picanha/persistence/project.hpp>
#include <picanha/plugin/plugin_manager.hpp>

#ifdef PICANHA_ENABLE_LLVM
#include <picanha/lift/lifting_service.hpp>
#include <picanha/lift/lifted_function.hpp>
#include <picanha/lift/export_lift_service.hpp>
#ifdef PICANHA_ENABLE_DECOMPILER
#include <picanha/lift/decompilation_service.hpp>
#endif
#endif

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <iostream>
#include <fstream>
#include <format>
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;
using namespace picanha;

// Forward declarations
int cmd_info(const std::string& binary_path);
int cmd_disasm(const std::string& binary_path, Address start_addr, std::size_t count, bool show_bytes);
int cmd_analyze(const std::string& binary_path, const std::string& output_path, bool verbose);
int cmd_functions(const std::string& binary_path);
int cmd_exports(const std::string& binary_path);
int cmd_imports(const std::string& binary_path);
int cmd_sections(const std::string& binary_path);
int cmd_cfg(const std::string& binary_path, Address func_addr);
#ifdef PICANHA_ENABLE_LLVM
int cmd_lift(const std::string& binary_path, Address addr, int opt_level, const std::string& output_file);
int cmd_export_lift(const std::string& binary_path, Address addr, int opt_level, 
                    bool with_deps, bool with_data, bool auto_compile,
                    const std::string& output_file, const std::string& data_output_file,
                    const std::string& entry_point, const std::string& remill_lib_path);
#ifdef PICANHA_ENABLE_DECOMPILER
int cmd_decompile(const std::string& binary_path, Address addr, const std::string& output_file);
#endif
#endif

void setup_logging(bool verbose, bool quiet) {
    auto console = spdlog::stdout_color_mt("console");
    spdlog::set_default_logger(console);

    if (quiet) {
        spdlog::set_level(spdlog::level::err);
    } else if (verbose) {
        spdlog::set_level(spdlog::level::debug);
    } else {
        spdlog::set_level(spdlog::level::info);
    }

    spdlog::set_pattern("[%^%l%$] %v");
}

int main(int argc, char** argv) {
    CLI::App app{"Picanha - x86_64 Disassembler for Windows PE/COFF binaries"};
    app.require_subcommand(1);

    // Global options
    bool verbose = false;
    bool quiet = false;
    app.add_flag("-v,--verbose", verbose, "Enable verbose output");
    app.add_flag("-q,--quiet", quiet, "Suppress non-error output");

    // Info command
    auto* info_cmd = app.add_subcommand("info", "Display binary information");
    std::string info_binary;
    info_cmd->add_option("binary", info_binary, "Path to binary file")->required()->check(CLI::ExistingFile);

    // Disasm command
    auto* disasm_cmd = app.add_subcommand("disasm", "Disassemble code at address");
    std::string disasm_binary;
    std::string disasm_addr_str = "entry";
    std::size_t disasm_count = 50;
    bool disasm_show_bytes = false;
    disasm_cmd->add_option("binary", disasm_binary, "Path to binary file")->required()->check(CLI::ExistingFile);
    disasm_cmd->add_option("-a,--address", disasm_addr_str, "Start address (hex) or 'entry'")->default_val("entry");
    disasm_cmd->add_option("-n,--count", disasm_count, "Number of instructions")->default_val(50);
    disasm_cmd->add_flag("-b,--bytes", disasm_show_bytes, "Show instruction bytes");

    // Analyze command
    auto* analyze_cmd = app.add_subcommand("analyze", "Perform full analysis");
    std::string analyze_binary;
    std::string analyze_output;
    bool analyze_verbose = false;
    analyze_cmd->add_option("binary", analyze_binary, "Path to binary file")->required()->check(CLI::ExistingFile);
    analyze_cmd->add_option("-o,--output", analyze_output, "Output project file (.pdb)");
    analyze_cmd->add_flag("-v,--verbose", analyze_verbose, "Verbose analysis output");

    // Functions command
    auto* functions_cmd = app.add_subcommand("functions", "List detected functions");
    std::string functions_binary;
    functions_cmd->add_option("binary", functions_binary, "Path to binary file")->required()->check(CLI::ExistingFile);

    // Exports command
    auto* exports_cmd = app.add_subcommand("exports", "List exported symbols");
    std::string exports_binary;
    exports_cmd->add_option("binary", exports_binary, "Path to binary file")->required()->check(CLI::ExistingFile);

    // Imports command
    auto* imports_cmd = app.add_subcommand("imports", "List imported symbols");
    std::string imports_binary;
    imports_cmd->add_option("binary", imports_binary, "Path to binary file")->required()->check(CLI::ExistingFile);

    // Sections command
    auto* sections_cmd = app.add_subcommand("sections", "List sections");
    std::string sections_binary;
    sections_cmd->add_option("binary", sections_binary, "Path to binary file")->required()->check(CLI::ExistingFile);

    // CFG command
    auto* cfg_cmd = app.add_subcommand("cfg", "Build and display CFG for a function");
    std::string cfg_binary;
    std::string cfg_addr_str;
    cfg_cmd->add_option("binary", cfg_binary, "Path to binary file")->required()->check(CLI::ExistingFile);
    cfg_cmd->add_option("address", cfg_addr_str, "Function address (hex)")->required();

#ifdef PICANHA_ENABLE_LLVM
    // Lift command
    auto* lift_cmd = app.add_subcommand("lift", "Lift function to LLVM IR");
    std::string lift_binary;
    std::string lift_addr_str;
    int lift_opt_level = 0;
    std::string lift_output;
    lift_cmd->add_option("binary", lift_binary, "Path to binary file")->required()->check(CLI::ExistingFile);
    lift_cmd->add_option("address", lift_addr_str, "Function address (hex)")->required();
    lift_cmd->add_option("-O,--opt-level", lift_opt_level, "Optimization level (0-3)")->default_val(0)->check(CLI::Range(0, 3));
    lift_cmd->add_option("-o,--output", lift_output, "Output file for IR");

    // Export lift command - produces compile-ready IR with remill runtime
    auto* export_lift_cmd = app.add_subcommand("export-lift", "Export function as compile-ready LLVM IR");
    std::string export_lift_binary;
    std::string export_lift_addr_str;
    int export_lift_opt_level = 0;
    bool export_lift_with_deps = false;
    bool export_lift_with_data = false;
    bool export_lift_auto_compile = false;
    std::string export_lift_output;
    std::string export_lift_data_output;
    std::string export_lift_entry_point;
    std::string export_lift_remill_lib;
    export_lift_cmd->add_option("binary", export_lift_binary, "Path to binary file")->required()->check(CLI::ExistingFile);
    export_lift_cmd->add_option("address", export_lift_addr_str, "Function address (hex)")->required();
    export_lift_cmd->add_option("-O,--opt-level", export_lift_opt_level, "Optimization level (0-3)")->default_val(0)->check(CLI::Range(0, 3));
    export_lift_cmd->add_flag("-d,--with-deps", export_lift_with_deps, "Include lifted dependencies");
    export_lift_cmd->add_flag("--with-data", export_lift_with_data, "Include data sections in separate file");
    export_lift_cmd->add_option("-o,--output", export_lift_output, "Output file for IR (required)")->required();
    export_lift_cmd->add_option("--data-output", export_lift_data_output, "Output file for data sections (with --with-data)");
    export_lift_cmd->add_option("--entry-point", export_lift_entry_point, "Entry point symbol name for linking (defaults to lifted function name)");
    export_lift_cmd->add_flag("--compile", export_lift_auto_compile, "Automatically compile and link the output");
    export_lift_cmd->add_option("--remill-lib", export_lift_remill_lib, "Path to remill runtime library (.lib file) for linking");

#ifdef PICANHA_ENABLE_DECOMPILER
    // Decompile command
    auto* decompile_cmd = app.add_subcommand("decompile", "Decompile function to C code");
    std::string decompile_binary;
    std::string decompile_addr_str;
    std::string decompile_output;
    decompile_cmd->add_option("binary", decompile_binary, "Path to binary file")->required()->check(CLI::ExistingFile);
    decompile_cmd->add_option("address", decompile_addr_str, "Function address (hex)")->required();
    decompile_cmd->add_option("-o,--output", decompile_output, "Output file for C code");
#endif
#endif

    // Parse
    CLI11_PARSE(app, argc, argv);

    // Setup logging
    setup_logging(verbose, quiet);

    // Execute subcommand
    if (*info_cmd) {
        return cmd_info(info_binary);
    } else if (*disasm_cmd) {
        Address start_addr = INVALID_ADDRESS;
        if (disasm_addr_str != "entry") {
            start_addr = std::stoull(disasm_addr_str, nullptr, 16);
        }
        return cmd_disasm(disasm_binary, start_addr, disasm_count, disasm_show_bytes);
    } else if (*analyze_cmd) {
        return cmd_analyze(analyze_binary, analyze_output, analyze_verbose);
    } else if (*functions_cmd) {
        return cmd_functions(functions_binary);
    } else if (*exports_cmd) {
        return cmd_exports(exports_binary);
    } else if (*imports_cmd) {
        return cmd_imports(imports_binary);
    } else if (*sections_cmd) {
        return cmd_sections(sections_binary);
    } else if (*cfg_cmd) {
        Address addr = std::stoull(cfg_addr_str, nullptr, 16);
        return cmd_cfg(cfg_binary, addr);
    }
#ifdef PICANHA_ENABLE_LLVM
    else if (*lift_cmd) {
        Address addr = std::stoull(lift_addr_str, nullptr, 16);
        return cmd_lift(lift_binary, addr, lift_opt_level, lift_output);
    }
    else if (*export_lift_cmd) {
        Address addr = std::stoull(export_lift_addr_str, nullptr, 16);
        return cmd_export_lift(export_lift_binary, addr, export_lift_opt_level, 
                               export_lift_with_deps, export_lift_with_data, export_lift_auto_compile,
                               export_lift_output, export_lift_data_output,
                               export_lift_entry_point, export_lift_remill_lib);
    }
#ifdef PICANHA_ENABLE_DECOMPILER
    else if (*decompile_cmd) {
        Address addr = std::stoull(decompile_addr_str, nullptr, 16);
        return cmd_decompile(decompile_binary, addr, decompile_output);
    }
#endif
#endif

    return 0;
}

std::shared_ptr<loader::Binary> load_binary(const std::string& path) {
    auto result = loader::Binary::load_file(path);
    if (!result) {
        spdlog::error("Failed to load binary: {} - {}", path, result.error().message());
        return nullptr;
    }
    return std::move(*result);
}

int cmd_info(const std::string& binary_path) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    std::cout << "Binary Information\n";
    std::cout << "==================\n\n";

    auto range = binary->address_range();
    auto image_size = range.end - range.start;

    std::cout << std::format("File:         {}\n", fs::path(binary_path).filename().string());
    std::cout << std::format("Format:       {}\n", binary->format() == loader::BinaryFormat::PE64 ? "PE64" : "PE32");
    std::cout << std::format("Architecture: {}\n", binary->is_64bit() ? "x86_64" : "x86");
    std::cout << std::format("Image Base:   0x{:016X}\n", binary->image_base());
    std::cout << std::format("Image Size:   0x{:X} ({} bytes)\n", image_size, image_size);
    std::cout << std::format("Entry Point:  0x{:016X}\n", binary->entry_point());
    std::cout << std::format("Sections:     {}\n", binary->sections().size());

    std::cout << "\n";
    return 0;
}

// Simple symbol resolver for CLI
class CLISymbolResolver : public iced_x86::SymbolResolver {
public:
    CLISymbolResolver(std::shared_ptr<loader::Binary> binary, const analysis::SymbolTable& symbols)
        : binary_(binary), symbols_(symbols) {}

    std::optional<iced_x86::SymbolResult> try_get_symbol(
        const iced_x86::Instruction& /*instruction*/,
        int /*operand*/, int /*instruction_operand*/,
        uint64_t address, int address_size) override
    {
        Address addr = static_cast<Address>(address);

        // Check symbol table (imports, exports)
        if (auto* sym = symbols_.find_at(addr)) {
            if (!sym->name.empty()) {
                return iced_x86::SymbolResult(address, sym->name);
            }
        }

        // Check if it's a function start from exception directory
        if (auto* func = binary_->find_function(addr)) {
            if (func->begin_address == addr) {
                if (auto name = binary_->get_symbol_name(addr)) {
                    return iced_x86::SymbolResult(address, *name);
                }
                return iced_x86::SymbolResult(address, std::format("sub_{:X}", addr));
            }
        }

        // Check if address is in a data section (.data, .rdata, etc.)
        if (auto* section = binary_->find_section(addr)) {
            if (!section->is_executable()) {
                // Use size-based prefix
                std::string_view prefix;
                switch (address_size) {
                    case 1:  prefix = "byte"; break;
                    case 2:  prefix = "word"; break;
                    case 4:  prefix = "dword"; break;
                    case 8:  prefix = "qword"; break;
                    case 16: prefix = "oword"; break;
                    default: prefix = "unk"; break;
                }
                return iced_x86::SymbolResult(address, std::format("{}_{:X}", prefix, addr));
            }
        }

        return std::nullopt;
    }

private:
    std::shared_ptr<loader::Binary> binary_;
    const analysis::SymbolTable& symbols_;
};

int cmd_disasm(const std::string& binary_path, Address start_addr, std::size_t count, bool show_bytes) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    // Build symbol table from binary
    analysis::SymbolTable symbols;
    symbols.build_from_binary(binary);
    spdlog::info("Loaded {} symbols ({} imports, {} exports)",
        symbols.count(), symbols.count_imports(), symbols.count_exports());

    // Use entry point if no address specified
    if (start_addr == INVALID_ADDRESS) {
        start_addr = binary->entry_point();
    }

    std::cout << std::format("Disassembly at 0x{:016X}\n", start_addr);
    std::cout << std::string(60, '=') << "\n\n";

    disasm::Decoder decoder;
    iced_x86::IntelFormatter formatter;
    CLISymbolResolver resolver(binary, symbols);
    formatter.set_symbol_resolver(&resolver);

    Address current = start_addr;
    std::size_t decoded = 0;

    while (decoded < count) {
        auto bytes = binary->read(current, 15);
        if (!bytes || bytes->empty()) {
            std::cout << std::format("0x{:016X}  <invalid address>\n", current);
            break;
        }

        auto instr = decoder.decode(*bytes, current);
        if (instr.length() == 0) {
            std::cout << std::format("0x{:016X}  db 0x{:02X}  ; invalid\n", current, (*bytes)[0]);
            current++;
            decoded++;
            continue;
        }

        // Format output
        std::cout << std::format("0x{:016X}  ", current);

        if (show_bytes) {
            std::string hex;
            for (std::size_t i = 0; i < instr.length() && i < bytes->size(); ++i) {
                hex += std::format("{:02X} ", (*bytes)[i]);
            }
            // Pad to fixed width
            while (hex.length() < 30) hex += "   ";
            std::cout << hex;
        }

        std::string formatted = formatter.format_to_string(instr.raw());
        std::cout << formatted << "\n";

        current += instr.length();
        decoded++;

        // Stop at return instructions
        if (instr.is_return()) {
            std::cout << "\n";
        }
    }

    return 0;
}

int cmd_analyze(const std::string& binary_path, const std::string& output_path, bool verbose) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    auto start_time = std::chrono::high_resolution_clock::now();

    spdlog::info("Starting analysis of {}", fs::path(binary_path).filename().string());
    
    // Set verbose logging if requested
    if (verbose) {
        spdlog::set_level(spdlog::level::debug);
        spdlog::debug("Verbose logging enabled");
    }

    // Create analysis context
    auto context = std::make_shared<disasm::DisassemblyContext>(binary);
    analysis::SymbolTable symbols;
    analysis::XRefManager xrefs;

    // Detect functions (this also builds CFGs)
    spdlog::info("Detecting functions...");
    analysis::FunctionDetectorConfig detector_config;
    detector_config.build_cfg = true;
    detector_config.analyze_calls = true;
    analysis::FunctionDetector detector(binary, context, detector_config);
    
    // Detect with progress callback
    detector.detect([](std::size_t current, std::size_t total, const char* phase) {
        spdlog::info("Analysis phase {}/{}: {}", current, total, phase);
    });

    auto& functions = detector.functions();
    spdlog::info("Found {} functions", functions.size());

    // Count total blocks from already-built CFGs
    std::size_t total_blocks = 0;
    for (auto& func : functions) {
        if (func.cfg().block_count() > 0) {
            total_blocks += func.cfg().block_count();
        }
    }

    spdlog::info("Total basic blocks: {}", total_blocks);

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    spdlog::info("Analysis completed in {} ms", duration.count());

    // Save to project file if specified
    if (!output_path.empty()) {
        spdlog::info("Saving project to {}", output_path);

        persistence::Project project;
        std::string name = fs::path(binary_path).stem().string();

        auto create_result = project.create(output_path, name);
        if (!create_result) {
            spdlog::error("Failed to create project file");
            return 1;
        }

        auto funcs_result = project.save_functions(functions);
        (void)funcs_result;

        auto syms_result = project.save_symbols(symbols);
        (void)syms_result;

        auto xrefs_result = project.save_xrefs(xrefs);
        (void)xrefs_result;

        spdlog::info("Project saved successfully");
    }

    // Print summary
    std::cout << "\nAnalysis Summary\n";
    std::cout << "================\n";
    std::cout << std::format("Functions:    {}\n", functions.size());
    std::cout << std::format("Basic Blocks: {}\n", total_blocks);
    std::cout << std::format("Symbols:      {}\n", symbols.count());
    std::cout << std::format("XRefs:        {}\n", xrefs.count());
    std::cout << std::format("Time:         {} ms\n", duration.count());

    return 0;
}

int cmd_functions(const std::string& binary_path) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    std::cerr << "[DEBUG] Creating disassembly context...\n";
    std::cerr.flush();

    // Quick function detection
    auto context = std::make_shared<disasm::DisassemblyContext>(binary);

    std::cerr << "[DEBUG] Creating function detector...\n";
    std::cerr.flush();

    // Skip CFG building for quick function listing
    analysis::FunctionDetectorConfig config;
    config.build_cfg = false;
    config.analyze_calls = false;

    analysis::FunctionDetector detector(binary, context, config);

    detector.detect([](std::size_t current, std::size_t total, const char* phase) {
        std::cerr << std::format("[DEBUG] Phase {}/{}: {}\n", current, total, phase);
        std::cerr.flush();
    });

    auto& functions = detector.functions();

    std::cout << std::format("Functions ({} total)\n", functions.size());
    std::cout << std::string(60, '=') << "\n\n";

    std::cout << std::format("{:<18} {:<12} {}\n", "Address", "Size", "Name");
    std::cout << std::string(60, '-') << "\n";

    for (const auto& func : functions) {
        std::string name = func.name().empty() ?
            std::format("sub_{:X}", func.start_address()) : func.name();
        std::cout << std::format("0x{:016X} {:>10}  {}\n",
            func.start_address(), func.size(), name);
    }

    return 0;
}

int cmd_exports(const std::string& binary_path) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    auto* exports_info = binary->exports();
    if (!exports_info) {
        std::cout << "No exports found\n";
        return 0;
    }
    const auto& exports = exports_info->exports;

    std::cout << std::format("Exports ({} total)\n", exports.size());
    std::cout << std::string(70, '=') << "\n\n";

    std::cout << std::format("{:<18} {:<8} {}\n", "Address", "Ordinal", "Name");
    std::cout << std::string(70, '-') << "\n";

    for (const auto& exp : exports) {
        std::cout << std::format("0x{:016X} {:>7}  {}\n",
            exp.address, exp.ordinal, exp.name);
    }

    return 0;
}

int cmd_imports(const std::string& binary_path) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    auto* imports_info = binary->imports();
    if (!imports_info) {
        std::cout << "No imports found\n";
        return 0;
    }

    std::size_t total = 0;
    for (const auto& mod : imports_info->modules) {
        total += mod.functions.size();
    }

    std::cout << std::format("Imports ({} total)\n", total);
    std::cout << std::string(80, '=') << "\n\n";

    Address image_base = binary->image_base();
    for (const auto& mod : imports_info->modules) {
        std::cout << std::format("\n[{}]\n", mod.name);
        for (const auto& func : mod.functions) {
            Address iat_va = image_base + func.iat_rva;
            std::cout << std::format("  0x{:016X}  {}\n", iat_va, func.name);
        }
    }

    return 0;
}

int cmd_sections(const std::string& binary_path) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    auto sections = binary->sections();

    std::cout << std::format("Sections ({} total)\n", sections.size());
    std::cout << std::string(90, '=') << "\n\n";

    std::cout << std::format("{:<10} {:<18} {:<18} {:<12} {}\n",
        "Name", "Virtual Addr", "Virtual Size", "Raw Size", "Flags");
    std::cout << std::string(90, '-') << "\n";

    for (const auto& sec : sections) {
        std::string flags;
        if (sec.is_executable()) flags += "X";
        if (has_permission(sec.permissions, MemoryPermissions::Read)) flags += "R";
        if (sec.is_writable()) flags += "W";

        std::cout << std::format("{:<10} 0x{:016X} 0x{:016X} {:>10}  {}\n",
            sec.name, sec.virtual_address, sec.virtual_size, sec.file_size, flags);
    }

    return 0;
}

int cmd_cfg(const std::string& binary_path, Address func_addr) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    // Check if we have function bounds from exception info
    const auto* func_entry = binary->find_function(func_addr);

    analysis::CFGBuilderConfig cfg_config;
    cfg_config.function_start = func_addr;
    if (func_entry) {
        cfg_config.function_end = func_entry->end_address;
        std::cout << std::format("Function bounds from exception info: 0x{:X} - 0x{:X}\n",
            func_entry->begin_address, func_entry->end_address);
    }

    analysis::CFGBuilder builder(binary, cfg_config);
    auto cfg = builder.build(func_addr);

    if (!cfg) {
        std::cout << "Failed to build CFG\n";
        return 1;
    }

    std::cout << std::format("\nCFG for function at 0x{:016X}\n", func_addr);
    std::cout << std::string(60, '=') << "\n\n";

    std::cout << std::format("Basic blocks: {}\n", cfg->block_count());
    std::cout << std::format("Entry block:  {}\n", cfg->entry_block_id());
    std::cout << std::format("Exit blocks:  {}\n", cfg->exit_blocks().size());
    std::cout << "\n";

    std::cout << "Blocks:\n";
    std::cout << std::string(60, '-') << "\n";

    cfg->for_each_block([](const analysis::BasicBlock& block) {
        std::cout << std::format("  Block {}: 0x{:X} - 0x{:X} ({} instructions)\n",
            block.id(), block.start_address(), block.end_address(),
            block.instruction_count());

        // Show successors
        if (!block.successors().empty()) {
            std::cout << "    Successors: ";
            for (const auto& succ : block.successors()) {
                std::cout << std::format("{} ", succ.target);
            }
            std::cout << "\n";
        }
    });

    return 0;
}

#ifdef PICANHA_ENABLE_LLVM
int cmd_lift(const std::string& binary_path, Address addr, int opt_level, const std::string& output_file) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    std::cout << std::format("Lifting function at 0x{:X}...\n", addr);

    // Create lifting service
    lift::LiftingService service(binary);
    if (!service.initialize()) {
        std::cerr << "Failed to initialize lifting service: " << service.error_message() << "\n";
        return 1;
    }

    // Lift the function
    auto result = service.lift_address(addr);
    if (!result.success) {
        std::cerr << "Failed to lift function: " << result.error << "\n";
        return 1;
    }

    std::cout << "Lifting successful!\n\n";

    // Apply optimization if requested
    if (opt_level > 0 && result.lifted) {
        auto level = static_cast<lift::OptimizationLevel>(opt_level);
        std::cout << std::format("Applying O{} optimization...\n", opt_level);
        if (!service.optimize(*result.lifted, level)) {
            std::cerr << "Warning: Optimization failed\n";
        }
    }

    // Get the IR text
    if (result.lifted) {
        std::string ir = result.lifted->ir_text();

        if (!output_file.empty()) {
            // Write to file
            std::ofstream out(output_file);
            if (out) {
                out << ir;
                std::cout << std::format("IR written to {}\n", output_file);
            } else {
                std::cerr << "Failed to open output file\n";
                return 1;
            }
        } else {
            // Print to stdout
            std::cout << std::string(60, '=') << "\n";
            std::cout << "LLVM IR:\n";
            std::cout << std::string(60, '-') << "\n";
            std::cout << ir << "\n";
        }
    }

    return 0;
}

int cmd_export_lift(const std::string& binary_path, Address addr, int opt_level, 
                    bool with_deps, bool with_data, bool auto_compile,
                    const std::string& output_file, const std::string& data_output_file,
                    const std::string& entry_point, const std::string& remill_lib_path) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    std::cout << std::format("Exporting lifted function at 0x{:X}...\n", addr);
    std::cout << "Configuration:\n";
    std::cout << std::format("  Optimization level: O{}\n", opt_level);
    std::cout << std::format("  Include dependencies: {}\n", with_deps ? "yes" : "no");
    std::cout << std::format("  Include data sections: {}\n", with_data ? "yes" : "no");
    std::cout << std::format("  Auto-compile: {}\n", auto_compile ? "yes" : "no");
    if (!entry_point.empty()) {
        std::cout << std::format("  Entry point: {}\n", entry_point);
    }
    if (!remill_lib_path.empty()) {
        std::cout << std::format("  Remill library: {}\n", remill_lib_path);
    }

    // Create export lift service
    lift::ExportLiftService service(binary);
    if (!service.initialize()) {
        std::cerr << "Failed to initialize export lift service: " << service.error_message() << "\n";
        return 1;
    }

    // Configure export
    lift::ExportLiftConfig config;
    config.opt_level = static_cast<lift::OptimizationLevel>(opt_level);
    config.include_dependencies = with_deps;
    config.include_data_sections = with_data;
    config.entry_point_name = entry_point;
    config.auto_compile = auto_compile;
    config.remill_lib_path = remill_lib_path;

    // Export the function
    auto result = service.export_function(addr, config);
    
    if (!result.success) {
        std::cerr << "Failed to export function: " << result.error_message << "\n";
        return 1;
    }

    std::cout << "Export successful!\n\n";

    // Write main IR to file
    {
        std::ofstream out(output_file);
        if (!out) {
            std::cerr << "Failed to open output file: " << output_file << "\n";
            return 1;
        }
        out << result.code_ir;
        std::cout << std::format("Main IR written to {}\n", output_file);
    }

    // Write data sections if present
    std::string final_data_file;
    if (with_data && !result.data_ir.empty()) {
        final_data_file = data_output_file;
        if (final_data_file.empty()) {
            // Auto-generate data file name based on main output
            std::filesystem::path main_path(output_file);
            std::filesystem::path data_path = main_path.parent_path() / std::format("{}_data{}", 
                main_path.stem().string(), main_path.extension().string());
            final_data_file = data_path.string();
        }
        
        std::ofstream out(final_data_file);
        if (!out) {
            std::cerr << "Failed to open data output file: " << final_data_file << "\n";
            // Non-fatal: continue
            final_data_file.clear();
        } else {
            out << result.data_ir;
            std::cout << std::format("Data sections written to {}\n", final_data_file);
        }
    }

    // Print summary
    std::cout << "\n";
    std::cout << std::format("Lifted functions: {}\n", result.lifted_functions.size());
    for (size_t i = 0; i < result.lifted_functions.size(); ++i) {
        std::cout << std::format("  [{}] 0x{:016X}\n", i + 1, result.lifted_functions[i]);
    }
    
    if (!result.included_data_sections.empty()) {
        std::cout << std::format("Included data sections: {}\n", result.included_data_sections.size());
        for (const auto& sec : result.included_data_sections) {
            std::cout << std::format("  - {}\n", sec);
        }
    }

    // Show compilation results or instructions
    if (auto_compile) {
        if (result.compilation_success) {
            std::cout << "\nCompilation successful!\n";
            std::cout << std::format("  Output executable: {}\n", result.output_executable_path);
        } else {
            std::cout << "\nCompilation failed!\n";
            std::cout << std::format("  Error: {}\n", result.compilation_output);
        }
    } else {
        std::cout << "\nThe exported IR is compile-ready and can be compiled with:\n";
        std::string link_cmd = "  clang";
        if (with_data && !result.data_ir.empty() && !final_data_file.empty()) {
            std::cout << "  # Compile both files separately and link:\n";
            std::cout << std::format("  clang -c {} -o code.o\n", output_file);
            std::cout << std::format("  clang -c {} -o data.o\n", final_data_file);
            link_cmd += " code.o data.o";
        } else {
            link_cmd += std::format(" {}", output_file);
        }
        
        // Add entry point specification if provided
        if (!entry_point.empty()) {
            link_cmd += std::format(" -Wl,/ENTRY:{}", entry_point);
        }
        
        // Add remill library if provided
        if (!remill_lib_path.empty()) {
            link_cmd += std::format(" \"{}\"", remill_lib_path);
        }
        
        // Add Windows system libraries
        link_cmd += " -lkernel32 -luser32 -lshell32 -lucrt -lvcruntime -lmsvcrt";
        
        link_cmd += " -o output.exe";
        std::cout << link_cmd << "\n";
    }
    
    // Show unresolved symbols if any
    if (!result.unresolved_symbols.empty()) {
        std::cout << "\nWarning: The following symbols are unresolved:\n";
        for (const auto& sym : result.unresolved_symbols) {
            std::cout << std::format("  - {}\n", sym);
        }
        std::cout << "\nYou may need to provide additional libraries or object files.\n";
    }

    return 0;
}

#ifdef PICANHA_ENABLE_DECOMPILER
int cmd_decompile(const std::string& binary_path, Address addr, const std::string& output_file) {
    auto binary = load_binary(binary_path);
    if (!binary) return 1;

    std::cout << std::format("Decompiling function at 0x{:X}...\n", addr);

    // Create lifting service
    lift::LiftingService service(binary);
    if (!service.initialize()) {
        std::cerr << "Failed to initialize lifting service: " << service.error_message() << "\n";
        return 1;
    }

    // Check if decompiler is available
    if (!lift::DecompilationService::is_available()) {
        std::cerr << "Decompiler not available (Rellic not built)\n";
        return 1;
    }

    // Lift the function first
    std::cout << "Lifting to LLVM IR...\n";
    auto lift_result = service.lift_address(addr);
    if (!lift_result.success) {
        std::cerr << "Failed to lift function: " << lift_result.error << "\n";
        return 1;
    }

    // Skip optimization - DCE can remove the function if not marked as external
    // Rellic will handle necessary transformations

    // Decompile
    std::cout << "Decompiling to C...\n";
    lift::DecompilationService decompiler(service.context());
    lift::DecompilationConfig config;
    config.lower_switches = true;

    auto result = decompiler.decompile_function_copy(*lift_result.lifted, config);

    if (!result.success) {
        std::cerr << "Decompilation failed: " << result.error_message << "\n";
        return 1;
    }

    std::cout << "Decompilation successful!\n\n";

    if (!output_file.empty()) {
        // Write to file
        std::ofstream out(output_file);
        if (out) {
            out << result.code;
            std::cout << std::format("C code written to {}\n", output_file);
        } else {
            std::cerr << "Failed to open output file\n";
            return 1;
        }
    } else {
        // Print to stdout
        std::cout << std::string(60, '=') << "\n";
        std::cout << "Decompiled C code:\n";
        std::cout << std::string(60, '-') << "\n";
        std::cout << result.code << "\n";
    }

    return 0;
}
#endif
#endif
