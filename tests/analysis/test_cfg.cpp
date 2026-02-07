// CFG and basic block tests

#include <picanha/core/types.hpp>
#include <picanha/analysis/basic_block.hpp>
#include <picanha/analysis/cfg.hpp>

#include <gtest/gtest.h>

using namespace picanha;
using namespace picanha::analysis;

// BasicBlock tests
class BasicBlockTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a simple block
        block_ = std::make_unique<BasicBlock>(1, 0x1000, 0x1010);
    }

    std::unique_ptr<BasicBlock> block_;
};

TEST_F(BasicBlockTest, Construction) {
    EXPECT_EQ(block_->id(), 1);
    EXPECT_EQ(block_->start_address(), 0x1000);
    EXPECT_EQ(block_->end_address(), 0x1010);
    EXPECT_EQ(block_->size(), 0x10);
}

TEST_F(BasicBlockTest, AddressContainment) {
    EXPECT_TRUE(block_->contains(0x1000));
    EXPECT_TRUE(block_->contains(0x1008));
    EXPECT_TRUE(block_->contains(0x100F));
    EXPECT_FALSE(block_->contains(0x0FFF));
    EXPECT_FALSE(block_->contains(0x1010));
}

TEST_F(BasicBlockTest, EmptyInstructions) {
    EXPECT_EQ(block_->instruction_count(), 0);
    EXPECT_TRUE(block_->instructions().empty());
}

TEST_F(BasicBlockTest, AddInstruction) {
    Instruction instr{};
    instr.address = 0x1000;
    instr.length = 4;

    block_->add_instruction(instr);

    EXPECT_EQ(block_->instruction_count(), 1);
    EXPECT_EQ(block_->instructions()[0].address, 0x1000);
}

TEST_F(BasicBlockTest, Successors) {
    EXPECT_TRUE(block_->successors().empty());

    block_->add_successor(0x2000);
    block_->add_successor(0x3000);

    EXPECT_EQ(block_->successors().size(), 2);
    EXPECT_EQ(block_->successors()[0], 0x2000);
    EXPECT_EQ(block_->successors()[1], 0x3000);
}

TEST_F(BasicBlockTest, Predecessors) {
    EXPECT_TRUE(block_->predecessors().empty());

    block_->add_predecessor(0x0500);

    EXPECT_EQ(block_->predecessors().size(), 1);
    EXPECT_EQ(block_->predecessors()[0], 0x0500);
}

// CFG tests
class CFGTest : public ::testing::Test {
protected:
    void SetUp() override {
        cfg_ = std::make_unique<CFG>(0x1000);
    }

    std::unique_ptr<CFG> cfg_;
};

TEST_F(CFGTest, Construction) {
    EXPECT_EQ(cfg_->entry_address(), 0x1000);
    EXPECT_EQ(cfg_->block_count(), 0);
}

TEST_F(CFGTest, AddBlock) {
    auto& block = cfg_->create_block(0x1000, 0x1010);

    EXPECT_EQ(cfg_->block_count(), 1);
    EXPECT_NE(cfg_->entry_block(), nullptr);
    EXPECT_EQ(cfg_->entry_block()->start_address(), 0x1000);
}

TEST_F(CFGTest, FindBlock) {
    cfg_->create_block(0x1000, 0x1010);
    cfg_->create_block(0x1010, 0x1020);
    cfg_->create_block(0x1030, 0x1040);

    EXPECT_NE(cfg_->find_block(0x1000), nullptr);
    EXPECT_NE(cfg_->find_block(0x1010), nullptr);
    EXPECT_NE(cfg_->find_block(0x1030), nullptr);
    EXPECT_EQ(cfg_->find_block(0x2000), nullptr);
}

TEST_F(CFGTest, FindBlockContaining) {
    cfg_->create_block(0x1000, 0x1010);
    cfg_->create_block(0x1010, 0x1020);

    auto* block1 = cfg_->find_block_containing(0x1005);
    auto* block2 = cfg_->find_block_containing(0x1015);

    EXPECT_NE(block1, nullptr);
    EXPECT_NE(block2, nullptr);
    EXPECT_EQ(block1->start_address(), 0x1000);
    EXPECT_EQ(block2->start_address(), 0x1010);
}

TEST_F(CFGTest, Edges) {
    cfg_->create_block(0x1000, 0x1010);
    cfg_->create_block(0x1010, 0x1020);

    cfg_->add_edge(0x1000, 0x1010, EdgeType::Fallthrough);

    // Check that edge was added
    auto* block1 = cfg_->find_block(0x1000);
    auto* block2 = cfg_->find_block(0x1010);

    EXPECT_TRUE(std::find(block1->successors().begin(),
                         block1->successors().end(),
                         0x1010) != block1->successors().end());
    EXPECT_TRUE(std::find(block2->predecessors().begin(),
                         block2->predecessors().end(),
                         0x1000) != block2->predecessors().end());
}

TEST_F(CFGTest, IterateBlocks) {
    cfg_->create_block(0x1000, 0x1010);
    cfg_->create_block(0x1010, 0x1020);
    cfg_->create_block(0x1020, 0x1030);

    std::size_t count = 0;
    for (const auto& block : cfg_->blocks()) {
        count++;
        EXPECT_NE(block, nullptr);
    }

    EXPECT_EQ(count, 3);
}

// Test edge types
TEST(EdgeTypeTest, AllTypes) {
    EXPECT_NE(EdgeType::Fallthrough, EdgeType::Jump);
    EXPECT_NE(EdgeType::Jump, EdgeType::ConditionalTrue);
    EXPECT_NE(EdgeType::ConditionalTrue, EdgeType::ConditionalFalse);
    EXPECT_NE(EdgeType::ConditionalFalse, EdgeType::Call);
}

// Main function
int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
