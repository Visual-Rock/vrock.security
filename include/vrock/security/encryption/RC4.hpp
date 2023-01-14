#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::encryption::RC4 {
    /// @brief encrypts data using the RC4 algorithm
    /// @param data data to encrypt
    /// @param key key for encryption 
    /// @return encrypted data
    std::shared_ptr<utils::ByteArray> encrypt(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key);
    
    /// @brief decrypts data using the RC4 algorithm
    /// @param data data to decrypt
    /// @param key key for decryption 
    /// @return decrypted data
    std::shared_ptr<utils::ByteArray> decrypt(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key);
}