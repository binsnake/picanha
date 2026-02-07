# tests/analysis/CMakeLists.txt - Analysis tests

add_executable(test_cfg
    test_cfg.cpp
)

target_link_libraries(test_cfg
    PRIVATE
        picanha::core
        picanha::analysis
        GTest::gtest
        GTest::gtest_main
)

picanha_configure_target(test_cfg)

add_test(NAME CFGTest COMMAND test_cfg)
