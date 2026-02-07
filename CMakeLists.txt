cmake_minimum_required(VERSION 3.25)

# Enable compile_commands.json generation for intellisense
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(picanha
    VERSION 0.1.0
    DESCRIPTION "x86_64 Disassembler for Windows PE/COFF binaries"
    LANGUAGES CXX
)

# C++23 required
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# CMake modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# Include our cmake modules
include(CompilerFlags)
include(Dependencies)

# Options
option(PICANHA_BUILD_CLI "Build command-line interface" ON)
option(PICANHA_BUILD_GUI "Build ImGUI application" ON)
option(PICANHA_BUILD_GUI_QT "Build Qt6 application" OFF)
option(PICANHA_BUILD_TESTS "Build unit tests" ON)
option(PICANHA_BUILD_PLUGINS "Build example plugins" ON)
option(PICANHA_ENABLE_LLVM "Enable LLVM/Remill integration (requires LLVM)" OFF)
option(PICANHA_ENABLE_DECOMPILER "Enable Rellic decompilation (requires LLVM and Z3)" OFF)

# iced_x86 configuration - decoder and Intel formatter only
set(ICED_X86_NO_ENCODER ON CACHE BOOL "Disable iced encoder")
set(ICED_X86_NO_BLOCK_ENCODER ON CACHE BOOL "Disable iced block encoder")
set(ICED_X86_NO_INSTRUCTION_CREATE ON CACHE BOOL "Disable instruction creation")
set(ICED_X86_NO_INTEL_FORMATTER OFF CACHE BOOL "Enable Intel formatter")
set(ICED_X86_NO_GAS_FORMATTER ON CACHE BOOL "Disable GAS formatter")
set(ICED_X86_NO_MASM_FORMATTER ON CACHE BOOL "Disable MASM formatter")
set(ICED_X86_NO_NASM_FORMATTER ON CACHE BOOL "Disable NASM formatter")

# Third-party libraries
add_subdirectory(third_party)

# Core libraries
add_subdirectory(lib/core)
add_subdirectory(lib/loader)
add_subdirectory(lib/disasm)
add_subdirectory(lib/analysis)
add_subdirectory(lib/persistence)
add_subdirectory(lib/plugin)
add_subdirectory(lib/ui)

# Optional LLVM integration
if(PICANHA_ENABLE_LLVM)
    add_subdirectory(lib/lift)
endif()

# Applications
if(PICANHA_BUILD_CLI)
    add_subdirectory(app/cli)
endif()

if(PICANHA_BUILD_GUI)
    add_subdirectory(app/gui)
endif()

if(PICANHA_BUILD_GUI_QT)
    add_subdirectory(lib/ui-qt)
    add_subdirectory(app/gui-qt)
endif()

# Plugins
if(PICANHA_BUILD_PLUGINS)
    add_subdirectory(plugins)
endif()

# Tests
if(PICANHA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Copy compile_commands.json to project root for IDE support
if(CMAKE_EXPORT_COMPILE_COMMANDS)
    add_custom_target(copy_compile_commands ALL
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_BINARY_DIR}/compile_commands.json
            ${CMAKE_SOURCE_DIR}/compile_commands.json
        COMMENT "Copying compile_commands.json to source directory"
    )
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "Picanha Configuration Summary:")
message(STATUS "  Version:      ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler:     ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Build Type:   ${CMAKE_BUILD_TYPE}")
message(STATUS "  Build CLI:    ${PICANHA_BUILD_CLI}")
message(STATUS "  Build GUI:    ${PICANHA_BUILD_GUI}")
message(STATUS "  Build GUI Qt: ${PICANHA_BUILD_GUI_QT}")
message(STATUS "  Build Tests:  ${PICANHA_BUILD_TESTS}")
message(STATUS "  LLVM:         ${PICANHA_ENABLE_LLVM}")
message(STATUS "  Decompiler:   ${PICANHA_ENABLE_DECOMPILER}")
message(STATUS "")
