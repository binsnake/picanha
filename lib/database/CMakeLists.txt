# lib/database/CMakeLists.txt - Persistence layer library

add_library(picanha_database STATIC
    src/stub.cpp  # Placeholder until Stage 6
)

target_include_directories(picanha_database
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(picanha_database
    PUBLIC
        picanha::core
        picanha::analysis
        unofficial::sqlite3::sqlite3
        nlohmann_json::nlohmann_json
)

picanha_configure_target(picanha_database)
add_library(picanha::database ALIAS picanha_database)
