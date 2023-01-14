#include <gtest/gtest.h>

#include "vrock/security/encryption/AES.hpp"

TEST(AESECBEncryptTest, BasicAssertion) {
    auto data = std::make_shared<vrock::utils::ByteArray>("Plaintext");
    auto key = std::make_shared<vrock::utils::ByteArray>("KeyKeyKeyKeyKeyK");

    auto encrypted = vrock::security::AES::encrypt_ecb(data, key);
    EXPECT_EQ(encrypted->to_string(), vrock::utils::ByteArray::from_hex_string("c9aed1347dc38bfe3345cc5b33391487")->to_string());
    EXPECT_EQ(vrock::security::AES::decrypt_ecb(encrypted, key)->to_string(), "Plaintext");
}

TEST(AESCBCEncryptTest, BasicAssertion) {
    auto data = vrock::utils::ByteArray::from_string("Test");
    auto key = vrock::utils::ByteArray::from_hex_string("B10851065A82E228EE29CF3A8322DB6A");
    auto iv = vrock::utils::ByteArray::from_hex_string("AC0EF343B92D165D8E75703C7B3E0770");

    auto encrypted = vrock::security::AES::encrypt_cbc(data, key, iv);
    EXPECT_EQ(encrypted->to_string(), vrock::utils::ByteArray::from_hex_string("78f293772a958631d43de02e31b84673")->to_string());
    EXPECT_EQ(vrock::security::AES::decrypt_cbc(encrypted, key, iv)->to_string(), "Test");
}

TEST(AESGCMEncryptTest, BasicAssertion) {
    auto data = vrock::utils::ByteArray::from_hex_string("00000000000000000000000000000000");
    auto key = vrock::utils::ByteArray::from_hex_string("0000000000000000000000000000000000000000000000000000000000000000");
    auto iv = vrock::utils::ByteArray::from_hex_string("000000000000000000000000");
    auto aad = vrock::utils::ByteArray::from_hex_string("00000000000000000000000000000000");

    auto encrypted = vrock::security::AES::encrypt_gcm(data, key, iv, aad);
    EXPECT_EQ(encrypted->to_string(), vrock::utils::ByteArray::from_hex_string("cea7403d4d606b6e074ec5d3baf39d18ae9b1771dba9cf62b39be017940330b4")->to_string());
    EXPECT_EQ(vrock::security::AES::decrypt_gcm(encrypted, key, iv, aad)->to_string(), data->to_string());
}