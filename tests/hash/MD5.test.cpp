#include <gtest/gtest.h>

#include "vrock/security/hash/MD5.hpp"

TEST(MD5Test, BasicAssertion) {
    auto data = vrock::utils::ByteArray::from_string("Test");

    EXPECT_EQ(vrock::security::hash::MD5::hash(data)->to_hex_string(), "0cbc6611f5540bd0809a388dc95a615b");
}