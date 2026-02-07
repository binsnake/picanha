# lib/loader/CMakeLists.txt - PE/COFF loader library

add_library(picanha_loader STATIC
    # PE parsing
    src/pe_parser.cpp
    src/pe_sections.cpp
    src/pe_exports.cpp
    src/pe_imports.cpp
    src/pe_relocations.cpp
    src/pe_exceptions.cpp

    # Memory and binary abstraction
    src/memory_map.cpp
    src/binary.cpp
)

target_include_directories(picanha_loader
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(picanha_loader
    PUBLIC
        picanha::core
)

picanha_configure_target(picanha_loader)
add_library(picanha::loader ALIAS picanha_loader)
