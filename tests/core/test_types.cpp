// Core types tests

#include <picanha/core/types.hpp>
#include <picanha/core/instruction.hpp>

#include <gtest/gtest.h>

using namespace picanha;

// Test basic type definitions
TEST(TypesTest, AddressSizes) {
    EXPECT_EQ(sizeof(Address), 8);
    EXPECT_EQ(sizeof(Size), 8);
    EXPECT_EQ(sizeof(Offset), 8);
}

TEST(TypesTest, InvalidConstants) {
    EXPECT_EQ(INVALID_ADDRESS, ~Address{0});
    EXPECT_EQ(INVALID_FUNCTION_ID, ~FunctionId{0});
    EXPECT_EQ(INVALID_BLOCK_ID, ~BlockId{0});
}

TEST(TypesTest, ArchitectureEnum) {
    EXPECT_NE(Architecture::X86, Architecture::X86_64);
    EXPECT_NE(Architecture::X86, Architecture::Unknown);
}

// Test instruction structure
TEST(InstructionTest, DefaultConstruction) {
    Instruction instr{};

    EXPECT_EQ(instr.address, 0);
    EXPECT_EQ(instr.length, 0);
    EXPECT_EQ(instr.mnemonic[0], '\0');
    EXPECT_EQ(instr.operands[0], '\0');
}

TEST(InstructionTest, Classification) {
    Instruction instr{};

    // Default should not be any specific type
    EXPECT_FALSE(instr.is_branch());
    EXPECT_FALSE(instr.is_call());
    EXPECT_FALSE(instr.is_return());
    EXPECT_FALSE(instr.is_unconditional_branch());
    EXPECT_FALSE(instr.is_conditional_branch());
}

TEST(InstructionTest, BranchClassification) {
    Instruction instr{};

    // Set as unconditional jump
    instr.flags = static_cast<InstructionFlags>(
        static_cast<std::uint16_t>(InstructionFlags::Branch) |
        static_cast<std::uint16_t>(InstructionFlags::Unconditional)
    );

    EXPECT_TRUE(instr.is_branch());
    EXPECT_TRUE(instr.is_unconditional_branch());
    EXPECT_FALSE(instr.is_conditional_branch());
    EXPECT_FALSE(instr.is_call());
    EXPECT_FALSE(instr.is_return());
}

TEST(InstructionTest, CallClassification) {
    Instruction instr{};

    instr.flags = static_cast<InstructionFlags>(
        static_cast<std::uint16_t>(InstructionFlags::Branch) |
        static_cast<std::uint16_t>(InstructionFlags::Call)
    );

    EXPECT_TRUE(instr.is_branch());
    EXPECT_TRUE(instr.is_call());
    EXPECT_FALSE(instr.is_return());
}

TEST(InstructionTest, ReturnClassification) {
    Instruction instr{};

    instr.flags = static_cast<InstructionFlags>(
        static_cast<std::uint16_t>(InstructionFlags::Branch) |
        static_cast<std::uint16_t>(InstructionFlags::Return)
    );

    EXPECT_TRUE(instr.is_branch());
    EXPECT_TRUE(instr.is_return());
    EXPECT_FALSE(instr.is_call());
}

TEST(InstructionTest, BranchTarget) {
    Instruction instr{};
    instr.address = 0x1000;
    instr.branch_target = 0x2000;

    EXPECT_EQ(instr.branch_target, 0x2000);
    EXPECT_TRUE(instr.has_branch_target());
}

TEST(InstructionTest, NoBranchTarget) {
    Instruction instr{};
    instr.address = 0x1000;
    instr.branch_target = INVALID_ADDRESS;

    EXPECT_FALSE(instr.has_branch_target());
}

// Test memory operand
TEST(MemoryOperandTest, Construction) {
    MemoryOperand mem{};
    mem.base = Register::RAX;
    mem.index = Register::RBX;
    mem.scale = 4;
    mem.displacement = 0x100;

    EXPECT_EQ(mem.base, Register::RAX);
    EXPECT_EQ(mem.index, Register::RBX);
    EXPECT_EQ(mem.scale, 4);
    EXPECT_EQ(mem.displacement, 0x100);
}

// Main function
int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
