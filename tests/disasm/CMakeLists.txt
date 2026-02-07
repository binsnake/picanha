# tests/disasm/CMakeLists.txt - Disassembler tests

add_executable(test_decoder
    test_decoder.cpp
)

target_link_libraries(test_decoder
    PRIVATE
        picanha::core
        picanha::disasm
        GTest::gtest
        GTest::gtest_main
)

picanha_configure_target(test_decoder)

add_test(NAME DecoderTest COMMAND test_decoder)
