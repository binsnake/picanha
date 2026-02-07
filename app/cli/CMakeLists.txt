# app/cli/CMakeLists.txt - Command-line interface

add_executable(picanha_cli
    src/main.cpp
)

target_link_libraries(picanha_cli
    PRIVATE
        picanha::core
        picanha::loader
        picanha::disasm
        picanha::analysis
        picanha::persistence
        picanha::plugin
        CLI11::CLI11
        spdlog::spdlog_picanha
)

# Link lift library when LLVM is enabled
if(PICANHA_ENABLE_LLVM)
    target_link_libraries(picanha_cli PRIVATE picanha::lift)
    target_compile_definitions(picanha_cli PRIVATE PICANHA_ENABLE_LLVM)
endif()

picanha_configure_target(picanha_cli)

# Set output name
set_target_properties(picanha_cli PROPERTIES
    OUTPUT_NAME "picanha"
)
