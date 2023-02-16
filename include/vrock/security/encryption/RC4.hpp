#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::encryption::RC4
{
    /// @brief encrypts data using the RC4 algorithm
    /// @param data data to encrypt
    /// @param key key for encryption
    /// @return encrypted data
    auto encrypt( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key )
        -> std::shared_ptr<utils::ByteArray>;

    /// @brief decrypts data using the RC4 algorithm
    /// @param data data to decrypt
    /// @param key key for decryption
    /// @return decrypted data
    auto decrypt( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key )
        -> std::shared_ptr<utils::ByteArray>;
} // namespace vrock::security::encryption::RC4