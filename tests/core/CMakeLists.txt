# tests/core/CMakeLists.txt - Core type tests

add_executable(test_core_types
    test_types.cpp
)

target_link_libraries(test_core_types
    PRIVATE
        picanha::core
        GTest::gtest
        GTest::gtest_main
)

picanha_configure_target(test_core_types)

add_test(NAME CoreTypesTest COMMAND test_core_types)
