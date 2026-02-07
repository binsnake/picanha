# tests/CMakeLists.txt - Unit tests

find_package(GTest CONFIG REQUIRED)

include(GoogleTest)

# Core tests
add_subdirectory(core)

# Disassembler tests
add_subdirectory(disasm)

# Analysis tests
add_subdirectory(analysis)
