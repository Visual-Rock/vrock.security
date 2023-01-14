#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::encryption::AES {
    /// @brief Encrypts the data with AES in GCM mode
    /// @param data data to encrypt
    /// @param key key for the encryption
    /// @param iv initialization vector
    /// @param authentication_data additional authentication data
    /// @return the encrypted result
    std::shared_ptr<utils::ByteArray> encrypt_gcm(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key, std::shared_ptr<utils::ByteArray> iv, std::shared_ptr<utils::ByteArray> authentication_data);
    
    /// @brief Decrypts the data with AES in GCM mode
    /// @param data data to decrypt
    /// @param key key for the decryption
    /// @param iv initialization vector
    /// @param authentication_data additional authentication data
    /// @return decrypted result
    std::shared_ptr<utils::ByteArray> decrypt_gcm(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key, std::shared_ptr<utils::ByteArray> iv, std::shared_ptr<utils::ByteArray> authentication_data);

    /// @brief encrypts data in AES ECB mode
    /// @param data data to encrypt
    /// @param key key for the encryption
    /// @return the encrypted data
    std::shared_ptr<utils::ByteArray> encrypt_ecb(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key);
    
    /// @brief decrypts data in AES ECB mode
    /// @param data data to decrypt
    /// @param key key for the decryption
    /// @return the decrypted data
    std::shared_ptr<utils::ByteArray> decrypt_ecb(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key);

    /// @brief Encrypts the data with AES in CBC mode
    /// @param data data to encrypt
    /// @param key key for the encryption
    /// @param iv initialization vector
    /// @return the encrypted result
    std::shared_ptr<utils::ByteArray> encrypt_cbc(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key, std::shared_ptr<utils::ByteArray> iv);
    
    /// @brief Decrypts the data with AES in CBC mode
    /// @param data data to decrypt
    /// @param key key for the decryption
    /// @param iv initialization vector
    /// @return the decrypted result
    std::shared_ptr<utils::ByteArray> decrypt_cbc(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key, std::shared_ptr<utils::ByteArray> iv);
}