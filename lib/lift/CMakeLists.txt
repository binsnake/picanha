# lib/lift/CMakeLists.txt - LLVM/Remill lifting integration

# Remill dependencies should be installed at this location
set(REMILL_DEPS_INSTALL "${CMAKE_SOURCE_DIR}/remill/dependencies/install")

# Add remill dependencies to CMAKE_PREFIX_PATH FIRST before any find_package calls
list(PREPEND CMAKE_PREFIX_PATH "${REMILL_DEPS_INSTALL}")

# Bypass vcpkg for gflags/glog - use explicit paths
set(gflags_DIR "${REMILL_DEPS_INSTALL}/lib/cmake/gflags")
set(glog_DIR "${REMILL_DEPS_INSTALL}/lib/cmake/glog")

# Tell gflags to use namespaced targets (gflags::gflags) which glog expects
set(GFLAGS_USE_TARGET_NAMESPACE TRUE)

# Find gflags BEFORE glog (glog depends on gflags)
find_package(gflags CONFIG REQUIRED
    PATHS "${REMILL_DEPS_INSTALL}/lib/cmake/gflags"
    NO_DEFAULT_PATH
)
message(STATUS "Found gflags: ${GFLAGS_TARGET}")

# Find glog
find_package(glog CONFIG REQUIRED
    PATHS "${REMILL_DEPS_INSTALL}/lib/cmake/glog"
    NO_DEFAULT_PATH
)
message(STATUS "Found glog")

# Find LLVM from remill dependencies or system
find_package(LLVM CONFIG REQUIRED)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# Get LLVM libraries we need
llvm_map_components_to_libnames(LLVM_LIBS
    core
    support
    irreader
    bitreader
    bitwriter
    passes
    asmprinter
    x86info
    x86codegen
    x86asmparser
)

# Find XED
find_library(XED_LIBRARY xed
    HINTS "${REMILL_DEPS_INSTALL}/lib"
)
find_path(XED_INCLUDE_DIR xed/xed-interface.h
    HINTS "${REMILL_DEPS_INSTALL}/include"
)

# Remill library - can be built separately or as subproject
set(REMILL_SOURCE_DIR "${CMAKE_SOURCE_DIR}/remill")
set(REMILL_BUILD_DIR "${CMAKE_BINARY_DIR}/remill_build")

# Check if remill is already built/installed
find_library(REMILL_LIBRARY remill
    HINTS
        "${REMILL_DEPS_INSTALL}/lib"
        "${REMILL_BUILD_DIR}/lib"
)

if(NOT REMILL_LIBRARY)
    # Build remill as subproject
    message(STATUS "Building remill as subproject")

    set(REMILL_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(REMILL_ENABLE_INSTALL_TARGET OFF CACHE BOOL "" FORCE)

    add_subdirectory("${REMILL_SOURCE_DIR}" "${REMILL_BUILD_DIR}" EXCLUDE_FROM_ALL)

    # After adding subdirectory, remill target should be available
    set(REMILL_TARGET remill)
else()
    message(STATUS "Found remill library: ${REMILL_LIBRARY}")

    # Create imported target
    add_library(remill STATIC IMPORTED)
    set_target_properties(remill PROPERTIES
        IMPORTED_LOCATION "${REMILL_LIBRARY}"
    )
    set(REMILL_TARGET remill)
endif()

# Optional: Rellic decompilation support
set(RELLIC_SOURCES "")
set(RELLIC_INCLUDES "")
set(RELLIC_LIBS "")
set(RELLIC_DEFS "")

if(PICANHA_ENABLE_DECOMPILER)
    message(STATUS "Decompiler support enabled - looking for Rellic dependencies")

    # Find Z3 (required for Rellic)
    find_package(Z3 4.8 CONFIG QUIET)
    if(NOT Z3_FOUND)
        message(WARNING "Z3 not found - decompiler will be disabled")
        set(PICANHA_ENABLE_DECOMPILER OFF)
    endif()

    # Find Clang (required for Rellic)
    find_package(Clang CONFIG QUIET
        PATHS "${REMILL_DEPS_INSTALL}/lib/cmake/clang"
    )
    if(NOT Clang_FOUND)
        message(WARNING "Clang not found - decompiler will be disabled")
        set(PICANHA_ENABLE_DECOMPILER OFF)
    endif()
endif()

if(PICANHA_ENABLE_DECOMPILER)
    message(STATUS "Building with Rellic decompiler support")

    # Rellic source directory
    set(RELLIC_SOURCE_DIR "${CMAKE_SOURCE_DIR}/rellic")
    set(RELLIC_BUILD_DIR "${CMAKE_BINARY_DIR}/rellic_build")

    # Check if rellic is already built/installed
    find_library(RELLIC_LIBRARY rellic
        HINTS
            "${RELLIC_BUILD_DIR}/lib"
            "${CMAKE_BINARY_DIR}/lib"
    )

    if(NOT RELLIC_LIBRARY)
        # Build rellic as subproject
        message(STATUS "Building Rellic as subproject")

        set(RELLIC_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
        set(RELLIC_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)

        add_subdirectory("${RELLIC_SOURCE_DIR}" "${RELLIC_BUILD_DIR}" EXCLUDE_FROM_ALL)

        set(RELLIC_TARGET rellic)
    else()
        message(STATUS "Found Rellic library: ${RELLIC_LIBRARY}")

        # Create imported target
        add_library(rellic_imported STATIC IMPORTED)
        set_target_properties(rellic_imported PROPERTIES
            IMPORTED_LOCATION "${RELLIC_LIBRARY}"
        )
        set(RELLIC_TARGET rellic_imported)
    endif()

    list(APPEND RELLIC_SOURCES src/decompilation_service.cpp)
    list(APPEND RELLIC_INCLUDES "${RELLIC_SOURCE_DIR}/include")
    list(APPEND RELLIC_LIBS ${RELLIC_TARGET} z3::libz3)
    list(APPEND RELLIC_DEFS PICANHA_ENABLE_DECOMPILER)

    # Add Clang libraries needed for AST manipulation and tooling
    list(APPEND RELLIC_LIBS
        clangAST
        clangBasic
        clangFrontend
        clangSerialization
        clangTooling
    )
else()
    # Still add the source file, but it will compile to stubs
    list(APPEND RELLIC_SOURCES src/decompilation_service.cpp)
endif()

# Our lifting library
add_library(picanha_lift STATIC
    src/lifting_context.cpp
    src/lifted_function.cpp
    src/trace_manager_impl.cpp
    src/ir_optimizer.cpp
    src/lifting_service.cpp
    src/export_lift_service.cpp
    ${RELLIC_SOURCES}
)

target_include_directories(picanha_lift
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${LLVM_INCLUDE_DIRS}
        ${REMILL_SOURCE_DIR}/include
        ${XED_INCLUDE_DIR}
        ${RELLIC_INCLUDES}
)

target_compile_definitions(picanha_lift
    PUBLIC
        PICANHA_ENABLE_LLVM
        ${RELLIC_DEFS}
    PRIVATE
        ${LLVM_DEFINITIONS}
)

target_link_libraries(picanha_lift
    PUBLIC
        picanha::core
        picanha::analysis
        picanha::loader
    PRIVATE
        ${REMILL_TARGET}
        ${LLVM_LIBS}
        ${XED_LIBRARY}
        glog::glog
        gflags::gflags
        ${RELLIC_LIBS}
)

# Remill requires C++17 minimum, but we use C++23 - should be compatible
target_compile_features(picanha_lift PUBLIC cxx_std_23)

picanha_configure_target(picanha_lift)
add_library(picanha::lift ALIAS picanha_lift)
