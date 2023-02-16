#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::encryption::AES
{
    /// @brief Padding Options for encryption and decryption
    enum Padding
    {
        NO_PADDING,
        ZEROS_PADDING,
        PKCS_PADDING,
        W3C_PADDING,
        ONE_AND_ZEROS_PADDING
    };

    /// @brief Encrypts the data with AES in GCM mode
    /// @param data data to encrypt
    /// @param key key for the encryption
    /// @param iv initialization vector
    /// @param authentication_data additional authentication data
    /// @return the encrypted result
    auto encrypt_gcm( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      const std::shared_ptr<utils::ByteArray> &iv,
                      const std::shared_ptr<utils::ByteArray> &authentication_data )
        -> std::shared_ptr<utils::ByteArray>;

    /// @brief Decrypts the data with AES in GCM mode
    /// @param data data to decrypt
    /// @param key key for the decryption
    /// @param iv initialization vector
    /// @param authentication_data additional authentication data
    /// @return decrypted result
    auto decrypt_gcm( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      const std::shared_ptr<utils::ByteArray> &iv,
                      const std::shared_ptr<utils::ByteArray> &authentication_data )
        -> std::shared_ptr<utils::ByteArray>;

    /// @brief encrypts data in AES ECB mode
    /// @param data data to encrypt
    /// @param key key for the encryption
    /// @param padding padding option for encryption
    /// @return the encrypted data
    auto encrypt_ecb( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      Padding padding = NO_PADDING ) -> std::shared_ptr<utils::ByteArray>;

    /// @brief decrypts data in AES ECB mode
    /// @param data data to decrypt
    /// @param key key for the decryption
    /// @param padding padding option for decryption
    /// @return the decrypted data
    auto decrypt_ecb( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      Padding padding = NO_PADDING ) -> std::shared_ptr<utils::ByteArray>;

    /// @brief Encrypts the data with AES in CBC mode
    /// @param data data to encrypt
    /// @param key key for the encryption
    /// @param iv initialization vector
    /// @param padding padding option for encryption
    /// @return the encrypted result
    auto encrypt_cbc( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      const std::shared_ptr<utils::ByteArray> &iv, Padding padding = NO_PADDING )
        -> std::shared_ptr<utils::ByteArray>;

    /// @brief Decrypts the data with AES in CBC mode
    /// @param data data to decrypt
    /// @param key key for the decryption
    /// @param iv initialization vector
    /// @param padding padding option for decryption
    /// @return the decrypted result
    auto decrypt_cbc( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      const std::shared_ptr<utils::ByteArray> &iv, Padding padding = NO_PADDING )
        -> std::shared_ptr<utils::ByteArray>;
} // namespace vrock::security::encryption::AES