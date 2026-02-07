# Signature matching plugin

add_library(plugin_signature_match MODULE
    signature_match.cpp
)

target_link_libraries(plugin_signature_match
    PRIVATE
        picanha::core
        picanha::analysis
        picanha::plugin
        xxHash::xxhash
        spdlog::spdlog
)

picanha_configure_target(plugin_signature_match)

set_target_properties(plugin_signature_match PROPERTIES
    OUTPUT_NAME "signature_match"
    PREFIX ""  # No 'lib' prefix on Linux
)
