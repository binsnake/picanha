# lib/ui/CMakeLists.txt - ImGui-based UI library

find_package(glfw3 CONFIG REQUIRED)
find_package(imgui CONFIG REQUIRED)
find_package(OpenGL REQUIRED)

add_library(picanha_ui STATIC
    src/app.cpp
    src/disasm_view.cpp
    src/hex_view.cpp
    src/function_list.cpp
    src/symbol_list.cpp
    src/xref_list.cpp
    src/imports_view.cpp
)

target_include_directories(picanha_ui
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(picanha_ui
    PUBLIC
        picanha::core
        picanha::loader
        picanha::analysis
        picanha::disasm
        picanha::persistence
        imgui::imgui
        glfw
        OpenGL::GL
        spdlog::spdlog_picanha
)

# Optional LLVM/lifting integration
if(PICANHA_ENABLE_LLVM)
    target_sources(picanha_ui PRIVATE
        src/ir_view.cpp
        src/optimized_view.cpp
        src/decompiled_view.cpp
    )
    target_link_libraries(picanha_ui PUBLIC picanha::lift)
    target_compile_definitions(picanha_ui PUBLIC PICANHA_ENABLE_LLVM)
endif()

picanha_configure_target(picanha_ui)
add_library(picanha::ui ALIAS picanha_ui)
