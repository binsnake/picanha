# lib/disasm/CMakeLists.txt - Disassembly engine library

add_library(picanha_disasm STATIC
    src/decoder.cpp
    src/flow_analyzer.cpp
    src/disassembly_context.cpp
    src/work_queue.cpp
    src/recursive_descent.cpp
)

target_include_directories(picanha_disasm
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(picanha_disasm
    PUBLIC
        picanha::core
        picanha::loader
)

picanha_configure_target(picanha_disasm)
add_library(picanha::disasm ALIAS picanha_disasm)
