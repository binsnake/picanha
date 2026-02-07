# app/gui/CMakeLists.txt - ImGUI application

find_package(glfw3 CONFIG REQUIRED)
find_package(imgui CONFIG REQUIRED)
find_package(OpenGL REQUIRED)

add_executable(picanha_gui WIN32
    src/main.cpp
)

target_link_libraries(picanha_gui
    PRIVATE
        picanha::core
        picanha::loader
        picanha::disasm
        picanha::analysis
        picanha::persistence
        picanha::plugin
        picanha::ui
        imgui::imgui
        glfw
        OpenGL::GL
        spdlog::spdlog_picanha
)

# Windows specific libraries
if(WIN32)
    target_link_libraries(picanha_gui
        PRIVATE
            shell32  # For CommandLineToArgvW
    )
endif()

picanha_configure_target(picanha_gui)

set_target_properties(picanha_gui PROPERTIES
    OUTPUT_NAME "picanha-gui"
)

# Install
install(TARGETS picanha_gui
    RUNTIME DESTINATION bin
)
