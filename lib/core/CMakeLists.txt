# lib/core/CMakeLists.txt - Core types and utilities library

add_library(picanha_core STATIC
    src/arena.cpp
    src/hash.cpp
)

target_include_directories(picanha_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(picanha_core
    PUBLIC
        TBB::tbb
        spdlog::spdlog_picanha
        xxHash::xxhash
        iced::x86
)

# Apply standard compiler settings
picanha_configure_target(picanha_core)

# Alias for cleaner cmake usage
add_library(picanha::core ALIAS picanha_core)
