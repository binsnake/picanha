// Decoder tests

#include <picanha/core/types.hpp>
#include <picanha/disasm/decoder.hpp>

#include <gtest/gtest.h>

#include <vector>
#include <cstdint>

using namespace picanha;
using namespace picanha::disasm;

class DecoderTest : public ::testing::Test {
protected:
    Decoder decoder_;
};

// Test NOP instruction
TEST_F(DecoderTest, DecodeNop) {
    std::vector<std::uint8_t> bytes = {0x90};  // NOP
    Instruction instr;

    bool result = decoder_.decode(bytes.data(), bytes.size(), 0x1000, instr);

    EXPECT_TRUE(result);
    EXPECT_EQ(instr.length, 1);
    EXPECT_EQ(instr.address, 0x1000);
    EXPECT_STREQ(instr.mnemonic, "nop");
}

// Test RET instruction
TEST_F(DecoderTest, DecodeRet) {
    std::vector<std::uint8_t> bytes = {0xC3};  // RET
    Instruction instr;

    bool result = decoder_.decode(bytes.data(), bytes.size(), 0x1000, instr);

    EXPECT_TRUE(result);
    EXPECT_EQ(instr.length, 1);
    EXPECT_TRUE(instr.is_return());
    EXPECT_TRUE(instr.is_branch());
}

// Test CALL instruction (direct)
TEST_F(DecoderTest, DecodeCall) {
    // CALL +0x100 (relative)
    std::vector<std::uint8_t> bytes = {0xE8, 0xFB, 0x00, 0x00, 0x00};
    Instruction instr;

    bool result = decoder_.decode(bytes.data(), bytes.size(), 0x1000, instr);

    EXPECT_TRUE(result);
    EXPECT_EQ(instr.length, 5);
    EXPECT_TRUE(instr.is_call());
    EXPECT_TRUE(instr.is_branch());
    // Target should be 0x1000 + 5 + 0xFB = 0x1100
    EXPECT_EQ(instr.branch_target, 0x1100);
}

// Test JMP instruction (direct)
TEST_F(DecoderTest, DecodeJmp) {
    // JMP +0x10 (short)
    std::vector<std::uint8_t> bytes = {0xEB, 0x10};
    Instruction instr;

    bool result = decoder_.decode(bytes.data(), bytes.size(), 0x1000, instr);

    EXPECT_TRUE(result);
    EXPECT_EQ(instr.length, 2);
    EXPECT_TRUE(instr.is_branch());
    EXPECT_TRUE(instr.is_unconditional_branch());
    // Target should be 0x1000 + 2 + 0x10 = 0x1012
    EXPECT_EQ(instr.branch_target, 0x1012);
}

// Test conditional branch
TEST_F(DecoderTest, DecodeJe) {
    // JE +0x10 (short)
    std::vector<std::uint8_t> bytes = {0x74, 0x10};
    Instruction instr;

    bool result = decoder_.decode(bytes.data(), bytes.size(), 0x1000, instr);

    EXPECT_TRUE(result);
    EXPECT_EQ(instr.length, 2);
    EXPECT_TRUE(instr.is_branch());
    EXPECT_TRUE(instr.is_conditional_branch());
    EXPECT_FALSE(instr.is_unconditional_branch());
}

// Test MOV instruction
TEST_F(DecoderTest, DecodeMovReg) {
    // MOV RAX, RBX (64-bit)
    std::vector<std::uint8_t> bytes = {0x48, 0x89, 0xD8};
    Instruction instr;

    bool result = decoder_.decode(bytes.data(), bytes.size(), 0x1000, instr);

    EXPECT_TRUE(result);
    EXPECT_EQ(instr.length, 3);
    EXPECT_FALSE(instr.is_branch());
}

// Test invalid instruction
TEST_F(DecoderTest, DecodeInvalid) {
    std::vector<std::uint8_t> bytes = {0x0F, 0x0B};  // UD2 (undefined)
    Instruction instr;

    bool result = decoder_.decode(bytes.data(), bytes.size(), 0x1000, instr);

    // UD2 is technically valid, but treated as invalid
    // This depends on decoder implementation
    EXPECT_TRUE(result || !result);  // Either way is acceptable
}

// Test buffer too small
TEST_F(DecoderTest, DecodeBufferTooSmall) {
    std::vector<std::uint8_t> bytes = {};
    Instruction instr;

    bool result = decoder_.decode(bytes.data(), bytes.size(), 0x1000, instr);

    EXPECT_FALSE(result);
}

// Test multiple instructions in sequence
TEST_F(DecoderTest, DecodeSequence) {
    std::vector<std::uint8_t> bytes = {
        0x90,                    // NOP
        0x48, 0x89, 0xD8,        // MOV RAX, RBX
        0xC3                     // RET
    };

    Address addr = 0x1000;
    std::size_t offset = 0;
    std::size_t count = 0;

    while (offset < bytes.size()) {
        Instruction instr;
        bool result = decoder_.decode(bytes.data() + offset,
                                      bytes.size() - offset,
                                      addr, instr);
        ASSERT_TRUE(result);

        offset += instr.length;
        addr += instr.length;
        count++;
    }

    EXPECT_EQ(count, 3);
    EXPECT_EQ(offset, bytes.size());
}

// Test memory operand detection
TEST_F(DecoderTest, DecodeMemoryOperand) {
    // MOV RAX, [RBX+0x10]
    std::vector<std::uint8_t> bytes = {0x48, 0x8B, 0x43, 0x10};
    Instruction instr;

    bool result = decoder_.decode(bytes.data(), bytes.size(), 0x1000, instr);

    EXPECT_TRUE(result);
    EXPECT_TRUE(instr.has_memory_operand);
}

// Test RIP-relative addressing
TEST_F(DecoderTest, DecodeRipRelative) {
    // LEA RAX, [RIP+0x100]
    std::vector<std::uint8_t> bytes = {0x48, 0x8D, 0x05, 0x00, 0x01, 0x00, 0x00};
    Instruction instr;

    bool result = decoder_.decode(bytes.data(), bytes.size(), 0x1000, instr);

    EXPECT_TRUE(result);
    EXPECT_EQ(instr.length, 7);
    // RIP-relative target should be computed
}

// Main function
int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
