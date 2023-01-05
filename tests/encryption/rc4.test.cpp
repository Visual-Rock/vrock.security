#include <gtest/gtest.h>

#include "vrock/security/encryption/RC4.hpp"

TEST(RC4EncryptTest, BasicAssertion) {
    auto data = std::make_shared<vrock::utils::ByteArray>("Plaintext");
    auto key = std::make_shared<vrock::utils::ByteArray>("Key");

    auto enc = vrock::security::RC4::encrypt(data, key);
    EXPECT_EQ(enc->to_string(), vrock::utils::ByteArray::from_hex_string("BBF316E8D940AF0AD3")->to_string());
    EXPECT_EQ(vrock::security::RC4::decrypt(enc, key)->to_string(), "Plaintext");
}