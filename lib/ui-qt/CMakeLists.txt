# lib/ui-qt/CMakeLists.txt - Qt6-based UI library

find_package(Qt6 REQUIRED COMPONENTS Widgets Concurrent)

qt_standard_project_setup()

# Enable Qt meta-object processing for targets in this directory
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

add_library(picanha_ui_qt STATIC
    src/main_window.cpp
    src/disasm_widget.cpp
    src/hex_widget.cpp
    src/function_list_widget.cpp
    src/symbol_list_widget.cpp
    src/xref_list_widget.cpp
    src/imports_widget.cpp
    src/log_widget.cpp
    src/syntax_highlighter.cpp
    # Headers with Q_OBJECT (needed for AUTOMOC)
    include/picanha/ui-qt/main_window.hpp
    include/picanha/ui-qt/disasm_widget.hpp
    include/picanha/ui-qt/hex_widget.hpp
    include/picanha/ui-qt/function_list_widget.hpp
    include/picanha/ui-qt/symbol_list_widget.hpp
    include/picanha/ui-qt/xref_list_widget.hpp
    include/picanha/ui-qt/imports_widget.hpp
    include/picanha/ui-qt/log_widget.hpp
    include/picanha/ui-qt/syntax_highlighter.hpp
)

target_include_directories(picanha_ui_qt
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(picanha_ui_qt
    PUBLIC
        picanha::core
        picanha::loader
        picanha::analysis
        picanha::disasm
        picanha::persistence
        Qt6::Widgets
        Qt6::Concurrent
        spdlog::spdlog_picanha
)

# Optional LLVM/lifting integration
if(PICANHA_ENABLE_LLVM)
    target_sources(picanha_ui_qt PRIVATE
        src/ir_widget.cpp
        src/optimized_widget.cpp
        src/decompiled_widget.cpp
        # Headers with Q_OBJECT (needed for AUTOMOC)
        include/picanha/ui-qt/ir_widget.hpp
        include/picanha/ui-qt/optimized_widget.hpp
        include/picanha/ui-qt/decompiled_widget.hpp
    )
    target_link_libraries(picanha_ui_qt PUBLIC picanha::lift)
    target_compile_definitions(picanha_ui_qt PUBLIC PICANHA_ENABLE_LLVM)
endif()

picanha_configure_target(picanha_ui_qt)
add_library(picanha::ui-qt ALIAS picanha_ui_qt)
