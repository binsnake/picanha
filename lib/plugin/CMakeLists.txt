# lib/plugin/CMakeLists.txt - Plugin system library

add_library(picanha_plugin STATIC
    src/plugin_manager.cpp
)

target_include_directories(picanha_plugin
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(picanha_plugin
    PUBLIC
        picanha::core
        picanha::analysis
        picanha::loader
        spdlog::spdlog_picanha
)

# Platform-specific linking
if(WIN32)
    # No additional libraries needed on Windows
else()
    target_link_libraries(picanha_plugin PRIVATE dl)
endif()

picanha_configure_target(picanha_plugin)
add_library(picanha::plugin ALIAS picanha_plugin)
