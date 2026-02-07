# app/gui-qt/CMakeLists.txt - Qt6-based GUI application

find_package(Qt6 REQUIRED COMPONENTS Widgets)

qt_standard_project_setup()

qt_add_executable(picanha_gui_qt WIN32
    src/main.cpp
)

target_link_libraries(picanha_gui_qt
    PRIVATE
        picanha::core
        picanha::loader
        picanha::disasm
        picanha::analysis
        picanha::persistence
        picanha::plugin
        picanha::ui-qt
        Qt6::Widgets
        spdlog::spdlog_picanha
)

# Windows specific libraries
if(WIN32)
    target_link_libraries(picanha_gui_qt
        PRIVATE
            shell32
    )
endif()

picanha_configure_target(picanha_gui_qt)

set_target_properties(picanha_gui_qt PROPERTIES
    OUTPUT_NAME "picanha-qt"
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
)

# Install
install(TARGETS picanha_gui_qt
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)

# On Windows, deploy Qt DLLs
if(WIN32)
    # Get the Qt bin directory
    get_target_property(QT_QMAKE_EXECUTABLE Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(QT_BIN_DIR "${QT_QMAKE_EXECUTABLE}" DIRECTORY)

    # Add post-build command to deploy Qt
    add_custom_command(TARGET picanha_gui_qt POST_BUILD
        COMMAND "${QT_BIN_DIR}/windeployqt.exe"
            --no-translations
            --no-system-d3d-compiler
            --no-opengl-sw
            "$<TARGET_FILE:picanha_gui_qt>"
        COMMENT "Deploying Qt..."
    )
endif()
