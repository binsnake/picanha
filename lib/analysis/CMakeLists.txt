# lib/analysis/CMakeLists.txt - CFG, xrefs, and pattern matching library

add_library(picanha_analysis STATIC
    # Basic blocks and CFG
    src/basic_block.cpp
    src/cfg.cpp
    src/cfg_builder.cpp

    # Functions
    src/function.cpp
    src/function_detector.cpp

    # Cross-references
    src/xref_manager.cpp

    # Symbols
    src/symbol_table.cpp

    # DAG and pattern matching (Stage 5)
    src/dag.cpp
    src/pattern.cpp
    src/pattern_matcher.cpp

    # Jump table and indirect call analysis
    src/jump_table.cpp
    src/indirect_resolver.cpp
    src/switch_analyzer.cpp
)

target_include_directories(picanha_analysis
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(picanha_analysis
    PUBLIC
        picanha::core
        picanha::disasm
        picanha::loader
        TBB::tbb
)

picanha_configure_target(picanha_analysis)
add_library(picanha::analysis ALIAS picanha_analysis)
