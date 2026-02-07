# Example function pass plugin

add_library(plugin_example_pass MODULE
    example_pass.cpp
)

target_link_libraries(plugin_example_pass
    PRIVATE
        picanha::core
        picanha::analysis
        picanha::plugin
        spdlog::spdlog
)

picanha_configure_target(plugin_example_pass)

set_target_properties(plugin_example_pass PROPERTIES
    OUTPUT_NAME "example_pass"
    PREFIX ""  # No 'lib' prefix on Linux
)
