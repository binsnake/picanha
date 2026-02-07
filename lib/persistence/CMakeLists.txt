# lib/persistence/CMakeLists.txt - Database and project persistence library

add_library(picanha_persistence STATIC
    src/database.cpp
    src/project.cpp
)

target_include_directories(picanha_persistence
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(picanha_persistence
    PUBLIC
        picanha::core
        picanha::analysis
        picanha::loader
        unofficial::sqlite3::sqlite3
        spdlog::spdlog_picanha
        # xxHash comes transitively from picanha::core
)

picanha_configure_target(picanha_persistence)
add_library(picanha::persistence ALIAS picanha_persistence)
