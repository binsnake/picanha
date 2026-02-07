# Picanha - x86_64 Disassembler Implementation Plan

## Project Overview
A modern x86_64 disassembler for Windows PE/COFF binaries with parallel processing, recursive descent analysis, CFG construction, and an IDA-like ImGUI interface.

## Architecture Overview

```
picanha/
├── CMakeLists.txt                    # Root CMake
├── cmake/                            # CMake modules
├── third_party/                      # iced_x86, imgui, etc.
├── lib/
│   ├── core/                         # Core types, utilities
│   ├── loader/                       # PE/COFF loader
│   ├── disasm/                       # Disassembly engine
│   ├── analysis/                     # CFG, xrefs, pattern matching
│   ├── database/                     # Persistence layer
│   └── plugin/                       # Plugin system
├── app/
│   ├── cli/                          # Command-line interface
│   └── gui/                          # ImGUI application
└── plugins/                          # Built-in plugins
```

---

## Stage 1: Build System & Core Foundation
**Goal**: CMake setup, core types, and iced_x86 integration

### Files to Create:

#### Build System
- `CMakeLists.txt` - Root CMake configuration
- `cmake/CompilerFlags.cmake` - LLVM/Clang compiler settings
- `cmake/Dependencies.cmake` - vcpkg/FetchContent dependencies
- `cmake/GenerateCompileCommands.cmake` - compile_commands.json setup
- `CMakePresets.json` - Build presets for Debug/Release/LLVM

#### Core Types (`lib/core/`)
- `lib/core/CMakeLists.txt`
- `lib/core/include/picanha/core/types.hpp` - Basic types (Address, Size, etc.)
- `lib/core/include/picanha/core/span.hpp` - Memory span utilities
- `lib/core/include/picanha/core/result.hpp` - Result<T, E> error handling
- `lib/core/include/picanha/core/bitflags.hpp` - Bitflag utilities
- `lib/core/include/picanha/core/hash.hpp` - Fast hashing (xxhash)
- `lib/core/include/picanha/core/arena.hpp` - Arena allocator for analysis
- `lib/core/include/picanha/core/parallel.hpp` - TBB wrappers

#### iced_x86 Integration (`third_party/`)
- `third_party/CMakeLists.txt`
- `third_party/iced_x86/CMakeLists.txt` - iced build config (decoder + fast_fmt only)
- `lib/core/include/picanha/core/instruction.hpp` - Thin wrapper over iced_x86::Instruction

---

## Stage 2: PE/COFF Loader
**Goal**: Windows binary loading and section parsing

### Files to Create:

#### Loader (`lib/loader/`)
- `lib/loader/CMakeLists.txt`
- `lib/loader/include/picanha/loader/binary.hpp` - Binary abstraction
- `lib/loader/include/picanha/loader/pe/pe_types.hpp` - PE structures
- `lib/loader/include/picanha/loader/pe/pe_parser.hpp` - PE header parsing
- `lib/loader/include/picanha/loader/pe/pe_sections.hpp` - Section handling
- `lib/loader/include/picanha/loader/pe/pe_exports.hpp` - Export directory
- `lib/loader/include/picanha/loader/pe/pe_imports.hpp` - Import directory
- `lib/loader/include/picanha/loader/pe/pe_relocations.hpp` - Relocations
- `lib/loader/include/picanha/loader/pe/pe_exceptions.hpp` - Exception directory (x64 unwind)
- `lib/loader/include/picanha/loader/memory_map.hpp` - Virtual memory mapping
- `lib/loader/src/pe_parser.cpp`
- `lib/loader/src/pe_sections.cpp`
- `lib/loader/src/pe_exports.cpp`
- `lib/loader/src/pe_imports.cpp`
- `lib/loader/src/pe_relocations.cpp`
- `lib/loader/src/pe_exceptions.cpp`
- `lib/loader/src/memory_map.cpp`

---

## Stage 3: Disassembly Engine
**Goal**: Parallel recursive descent disassembler

### Files to Create:

#### Disassembly (`lib/disasm/`)
- `lib/disasm/CMakeLists.txt`
- `lib/disasm/include/picanha/disasm/decoder.hpp` - Decoder wrapper
- `lib/disasm/include/picanha/disasm/instruction_info.hpp` - Extended instruction info
- `lib/disasm/include/picanha/disasm/flow_analyzer.hpp` - Flow control classification
- `lib/disasm/include/picanha/disasm/linear_sweep.hpp` - Linear sweep disassembly
- `lib/disasm/include/picanha/disasm/recursive_descent.hpp` - Recursive descent engine
- `lib/disasm/include/picanha/disasm/work_queue.hpp` - Parallel work queue (TBB)
- `lib/disasm/include/picanha/disasm/disassembly_context.hpp` - Shared analysis context
- `lib/disasm/src/decoder.cpp`
- `lib/disasm/src/instruction_info.cpp`
- `lib/disasm/src/flow_analyzer.cpp`
- `lib/disasm/src/linear_sweep.cpp`
- `lib/disasm/src/recursive_descent.cpp`
- `lib/disasm/src/work_queue.cpp`

---

## Stage 4: CFG & Cross-References
**Goal**: Control flow graph and reference tracking

### Files to Create:

#### Analysis (`lib/analysis/`)
- `lib/analysis/CMakeLists.txt`
- `lib/analysis/include/picanha/analysis/basic_block.hpp` - Basic block representation
- `lib/analysis/include/picanha/analysis/cfg.hpp` - Control flow graph
- `lib/analysis/include/picanha/analysis/cfg_builder.hpp` - CFG construction
- `lib/analysis/include/picanha/analysis/function.hpp` - Function representation
- `lib/analysis/include/picanha/analysis/function_detector.hpp` - Function boundary detection
- `lib/analysis/include/picanha/analysis/xref.hpp` - Cross-reference types
- `lib/analysis/include/picanha/analysis/xref_manager.hpp` - X-ref tracking and queries
- `lib/analysis/include/picanha/analysis/symbol.hpp` - Symbol types
- `lib/analysis/include/picanha/analysis/symbol_table.hpp` - Symbol management
- `lib/analysis/src/basic_block.cpp`
- `lib/analysis/src/cfg.cpp`
- `lib/analysis/src/cfg_builder.cpp`
- `lib/analysis/src/function.cpp`
- `lib/analysis/src/function_detector.cpp`
- `lib/analysis/src/xref_manager.cpp`
- `lib/analysis/src/symbol_table.cpp`

---

## Stage 5: DAG & Pattern Matching
**Goal**: Jump table and indirect call reconstruction via subgraph isomorphism

### Files to Create:

#### Pattern Matching (`lib/analysis/patterns/`)
- `lib/analysis/include/picanha/analysis/patterns/dag.hpp` - DAG representation
- `lib/analysis/include/picanha/analysis/patterns/dag_builder.hpp` - Instruction DAG construction
- `lib/analysis/include/picanha/analysis/patterns/pattern.hpp` - Pattern definition
- `lib/analysis/include/picanha/analysis/patterns/pattern_matcher.hpp` - Subgraph isomorphism (VF2)
- `lib/analysis/include/picanha/analysis/patterns/jump_table_patterns.hpp` - Jump table patterns
- `lib/analysis/include/picanha/analysis/patterns/indirect_call_patterns.hpp` - Indirect call patterns
- `lib/analysis/include/picanha/analysis/patterns/switch_analyzer.hpp` - Switch statement reconstruction
- `lib/analysis/src/patterns/dag.cpp`
- `lib/analysis/src/patterns/dag_builder.cpp`
- `lib/analysis/src/patterns/pattern_matcher.cpp`
- `lib/analysis/src/patterns/jump_table_patterns.cpp`
- `lib/analysis/src/patterns/indirect_call_patterns.cpp`
- `lib/analysis/src/patterns/switch_analyzer.cpp`

---

## Stage 6: Persistence Layer
**Goal**: Save/load analysis results (like IDA's .idb)

### Files to Create:

#### Database (`lib/database/`)
- `lib/database/CMakeLists.txt`
- `lib/database/include/picanha/database/database.hpp` - Database interface
- `lib/database/include/picanha/database/schema.hpp` - Database schema
- `lib/database/include/picanha/database/serialization.hpp` - Serialization utilities
- `lib/database/include/picanha/database/project.hpp` - Project file management
- `lib/database/include/picanha/database/snapshots.hpp` - Analysis snapshots
- `lib/database/src/database.cpp` - SQLite implementation
- `lib/database/src/schema.cpp`
- `lib/database/src/serialization.cpp`
- `lib/database/src/project.cpp`
- `lib/database/src/snapshots.cpp`

---

## Stage 7: Plugin System
**Goal**: Dynamic DLL plugin loading for function passes

### Files to Create:

#### Plugin System (`lib/plugin/`)
- `lib/plugin/CMakeLists.txt`
- `lib/plugin/include/picanha/plugin/plugin_api.hpp` - Plugin C API (ABI stable)
- `lib/plugin/include/picanha/plugin/plugin_interface.hpp` - Plugin C++ interface
- `lib/plugin/include/picanha/plugin/plugin_loader.hpp` - DLL loading
- `lib/plugin/include/picanha/plugin/plugin_manager.hpp` - Plugin lifecycle
- `lib/plugin/include/picanha/plugin/pass.hpp` - Function pass interface
- `lib/plugin/include/picanha/plugin/pass_manager.hpp` - Pass scheduling/execution
- `lib/plugin/include/picanha/plugin/hooks.hpp` - Event hooks for plugins
- `lib/plugin/src/plugin_loader.cpp`
- `lib/plugin/src/plugin_manager.cpp`
- `lib/plugin/src/pass_manager.cpp`

#### Example Plugin
- `plugins/example_pass/CMakeLists.txt`
- `plugins/example_pass/example_pass.cpp`

---

## Stage 8: Command-Line Interface
**Goal**: Functional CLI tool

### Files to Create:

#### CLI Application (`app/cli/`)
- `app/cli/CMakeLists.txt`
- `app/cli/src/main.cpp` - Entry point
- `app/cli/src/cli_parser.hpp` - Command-line parsing
- `app/cli/src/commands/analyze.hpp` - Analyze command
- `app/cli/src/commands/disasm.hpp` - Disassemble command
- `app/cli/src/commands/export.hpp` - Export command
- `app/cli/src/commands/info.hpp` - Binary info command
- `app/cli/src/output/text_output.hpp` - Text output formatter
- `app/cli/src/output/json_output.hpp` - JSON output formatter

---

## Stage 9: ImGUI Foundation
**Goal**: Basic ImGUI application shell with docking

### Files to Create:

#### GUI Application (`app/gui/`)
- `app/gui/CMakeLists.txt`
- `app/gui/src/main.cpp` - Entry point (Win32 + DirectX11/Vulkan)
- `app/gui/src/application.hpp` - Application class
- `app/gui/src/application.cpp`
- `app/gui/src/window.hpp` - Window management
- `app/gui/src/window.cpp`
- `app/gui/src/theme.hpp` - IDA-like dark theme
- `app/gui/src/theme.cpp`
- `app/gui/src/keybindings.hpp` - Keyboard shortcuts
- `app/gui/src/keybindings.cpp`

---

## Stage 10: GUI Core Views
**Goal**: Essential disassembly views

### Files to Create:

#### Views (`app/gui/views/`)
- `app/gui/src/views/view_base.hpp` - Base view class
- `app/gui/src/views/disasm_view.hpp` - Disassembly listing view
- `app/gui/src/views/disasm_view.cpp`
- `app/gui/src/views/hex_view.hpp` - Hex dump view
- `app/gui/src/views/hex_view.cpp`
- `app/gui/src/views/functions_view.hpp` - Functions list
- `app/gui/src/views/functions_view.cpp`
- `app/gui/src/views/xrefs_view.hpp` - Cross-references view
- `app/gui/src/views/xrefs_view.cpp`
- `app/gui/src/views/strings_view.hpp` - Strings view
- `app/gui/src/views/strings_view.cpp`

---

## Stage 11: GUI Advanced Views
**Goal**: Graph view and advanced navigation

### Files to Create:

#### Advanced Views
- `app/gui/src/views/graph_view.hpp` - CFG graph visualization
- `app/gui/src/views/graph_view.cpp`
- `app/gui/src/views/imports_view.hpp` - Imports list
- `app/gui/src/views/imports_view.cpp`
- `app/gui/src/views/exports_view.hpp` - Exports list
- `app/gui/src/views/exports_view.cpp`
- `app/gui/src/views/segments_view.hpp` - Segments/sections view
- `app/gui/src/views/segments_view.cpp`
- `app/gui/src/views/output_view.hpp` - Log/output console
- `app/gui/src/views/output_view.cpp`

#### Graph Layout
- `app/gui/src/graph/layout.hpp` - Graph layout algorithms
- `app/gui/src/graph/layout.cpp`
- `app/gui/src/graph/renderer.hpp` - Block rendering
- `app/gui/src/graph/renderer.cpp`

---

## Stage 12: Navigation & Search
**Goal**: IDA-like navigation features

### Files to Create:

#### Navigation
- `app/gui/src/navigation/history.hpp` - Navigation history (back/forward)
- `app/gui/src/navigation/history.cpp`
- `app/gui/src/navigation/bookmarks.hpp` - Bookmarks system
- `app/gui/src/navigation/bookmarks.cpp`
- `app/gui/src/navigation/goto_dialog.hpp` - Go to address dialog
- `app/gui/src/navigation/goto_dialog.cpp`

#### Search
- `app/gui/src/search/search_engine.hpp` - Search infrastructure
- `app/gui/src/search/search_engine.cpp`
- `app/gui/src/search/text_search.hpp` - Text/mnemonic search
- `app/gui/src/search/text_search.cpp`
- `app/gui/src/search/byte_search.hpp` - Byte pattern search
- `app/gui/src/search/byte_search.cpp`
- `app/gui/src/search/search_dialog.hpp` - Search UI
- `app/gui/src/search/search_dialog.cpp`

---

## Stage 13: Remill/LLVM Preparation
**Goal**: Infrastructure for future LLVM integration

### Files to Create:

#### LLVM Bridge (`lib/lift/`)
- `lib/lift/CMakeLists.txt`
- `lib/lift/include/picanha/lift/lifter.hpp` - Lifter interface
- `lib/lift/include/picanha/lift/llvm_context.hpp` - LLVM context wrapper
- `lib/lift/include/picanha/lift/ir_builder.hpp` - IR building utilities
- `lib/lift/include/picanha/lift/semantics.hpp` - x86_64 semantics (stubs)
- `lib/lift/src/lifter.cpp` - Placeholder implementation

---

## Dependencies

### Required (vcpkg.json)
```json
{
  "dependencies": [
    "tbb",
    "sqlite3",
    "imgui[docking-experimental,win32-binding,dx11-binding]",
    "spdlog",
    "nlohmann-json",
    "xxhash",
    "cli11"
  ]
}
```

### Optional (for Stage 13+)
- LLVM 21 (manual installation)
- Remill (submodule/FetchContent)

---

## Build Commands

```bash
# Configure with Clang/LLVM
cmake --preset=llvm-debug

# Build
cmake --build --preset=llvm-debug

# Generate compile_commands.json (automatic with preset)
```

---

## Key Design Decisions

1. **Parallel Analysis**: TBB concurrent containers + task groups for function-level parallelism
2. **Memory Efficiency**: Arena allocators for instructions/blocks, shared string interning
3. **Plugin ABI**: C API for binary compatibility, C++ convenience wrappers
4. **Database**: SQLite for simplicity, schema versioning for forward compatibility
5. **iced_x86 Config**: `ICED_X86_NO_ENCODER`, `ICED_X86_NO_BLOCK_ENCODER`, fast formatter only
6. **Graph Layout**: Sugiyama-based layered layout for CFG visualization

---

## Testing Strategy

Each stage includes unit tests:
- `tests/core/` - Core utilities
- `tests/loader/` - PE parsing
- `tests/disasm/` - Disassembly
- `tests/analysis/` - CFG, xrefs
- `tests/patterns/` - Pattern matching
- Integration tests with real binaries in `tests/binaries/`

---

## Notes

- Stage 1-4: Core functionality, can be used via CLI
- Stage 5-7: Advanced features
- Stage 8-12: GUI development
- Stage 13: Future LLVM/Remill integration
