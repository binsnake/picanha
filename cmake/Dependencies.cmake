# Dependencies.cmake - Find and configure project dependencies

include(FetchContent)

# vcpkg integration (if using vcpkg toolchain)
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

# TBB - Intel Threading Building Blocks
find_package(TBB CONFIG REQUIRED)
message(STATUS "Found TBB: ${TBB_VERSION}")

# SQLite3 - Database
find_package(unofficial-sqlite3 CONFIG REQUIRED)
message(STATUS "Found SQLite3")

# spdlog - Logging
find_package(spdlog CONFIG REQUIRED)
message(STATUS "Found spdlog: ${spdlog_VERSION}")

# For Clang, use spdlog in header-only mode with std::format to avoid fmt consteval issues
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Create a header-only interface target that just provides includes
    add_library(spdlog_headeronly INTERFACE)
    target_include_directories(spdlog_headeronly INTERFACE
        ${spdlog_INCLUDE_DIR}
        $<TARGET_PROPERTY:spdlog::spdlog,INTERFACE_INCLUDE_DIRECTORIES>
    )
    add_library(spdlog::spdlog_picanha ALIAS spdlog_headeronly)
    message(STATUS "Using spdlog in header-only mode for Clang")
else()
    # For other compilers, use the normal spdlog library
    add_library(spdlog::spdlog_picanha ALIAS spdlog::spdlog)
endif()

# nlohmann_json - JSON
find_package(nlohmann_json CONFIG REQUIRED)
message(STATUS "Found nlohmann_json: ${nlohmann_json_VERSION}")

# xxHash - Fast hashing
find_package(xxHash CONFIG REQUIRED)
message(STATUS "Found xxHash")

# CLI11 - Command line parsing
find_package(CLI11 CONFIG REQUIRED)
message(STATUS "Found CLI11: ${CLI11_VERSION}")

# ImGui - GUI (optional, for GUI build)
if(PICANHA_BUILD_GUI)
    find_package(imgui CONFIG REQUIRED)
    message(STATUS "Found ImGui: ${imgui_VERSION}")
endif()

# LLVM - Optional, for lifting
if(PICANHA_ENABLE_LLVM)
    # Prefer remill's bundled LLVM 17 over system LLVM
    set(REMILL_DEPS_INSTALL "${CMAKE_SOURCE_DIR}/remill/dependencies/install")
    find_package(LLVM CONFIG
        PATHS "${REMILL_DEPS_INSTALL}/lib/cmake/llvm"
        NO_DEFAULT_PATH
    )
    if(NOT LLVM_FOUND)
        # Fall back to system LLVM
        find_package(LLVM CONFIG)
    endif()

    if(LLVM_FOUND)
        message(STATUS "Found LLVM: ${LLVM_VERSION}")
        message(STATUS "LLVM include dirs: ${LLVM_INCLUDE_DIRS}")
        message(STATUS "LLVM definitions: ${LLVM_DEFINITIONS}")

        # NOTE: Do NOT add LLVM definitions globally with add_definitions()
        # as it breaks third-party code (e.g., Ghidra's decompiler with UNICODE).
        # LLVM definitions are applied only to picanha_lift target.
    else()
        message(WARNING "LLVM not found - lifting support disabled")
        set(PICANHA_ENABLE_LLVM OFF CACHE BOOL "" FORCE)
    endif()
endif()

# Helper function to link common dependencies
function(picanha_link_common_deps target)
    target_link_libraries(${target} PRIVATE
        TBB::tbb
        spdlog::spdlog_picanha
        nlohmann_json::nlohmann_json
        xxHash::xxhash
    )
endfunction()
