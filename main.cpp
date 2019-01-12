#include "gtest/gtest.h"
#include "log.h"
class Base : public ::testing::Test {
  public:
  Base() {}
  virtual ~Base() {}

  void SetUp()  {
     // Code here will be called immediately after the constructor (right
     // before each test).
  }

  void TearDown()  {
     // Code here will be called immediately after each test (right
     // before the destructor).
  }

  // Objects declared here can be used by all tests in the test case for Base.
};

class Derived : public Base {
  public:
  Derived() {}
  ~Derived() {}

  void SetUp()  {
     // Code here will be called immediately after the constructor (right
     // before each test).
  }

  void TearDown()  {
     // Code here will be called immediately after each test (right
     // before the destructor).
  }
  // Objects declared here can be used by all tests in the test case for Base.
};


TEST_F(Base, MethodBarDoesAbc) {
    ASSERT_TRUE(false) << "OOps";
}

TEST_F(Base, MethodBarDoesAbc1) {
    ASSERT_TRUE(false) << "OOps";
}

TEST_F(Derived, MethodBarDoesAbc) {
    ASSERT_TRUE(false) << "OOps";
}

TEST_F(Derived, MethodBarDoesAbc1) {
    ASSERT_TRUE(false) << "OOps";
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
