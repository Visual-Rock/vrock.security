#include <gtest/gtest.h>

#include "vrock/security/encryption/RC4.hpp"

TEST(RC4EncryptTest, BasicAssrtion) {
    auto data = std::make_shared<vrock::utils::ByteArray>("Plaintext");
    auto key = std::make_shared<vrock::utils::ByteArray>("Key");
}