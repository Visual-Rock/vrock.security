#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::hash::SHA2
{
    /// @brief hashes the data using the sha-224 algorithm
    /// @param data data to hash
    /// @return hash of the data
    auto sha224( const std::shared_ptr<utils::ByteArray> &data ) -> std::shared_ptr<utils::ByteArray>;

    /// @brief hashes the data using the sha-256 algorithm
    /// @param data data to hash
    /// @return hash of the data
    auto sha256( const std::shared_ptr<utils::ByteArray> &data ) -> std::shared_ptr<utils::ByteArray>;

    /// @brief hashes the data using the sha-384 algorithm
    /// @param data data to hash
    /// @return hash of the data
    auto sha384( const std::shared_ptr<utils::ByteArray> &data ) -> std::shared_ptr<utils::ByteArray>;

    /// @brief hashes the data using the sha-512 algorithm
    /// @param data data to hash
    /// @return hash of the data
    auto sha512( const std::shared_ptr<utils::ByteArray> &data ) -> std::shared_ptr<utils::ByteArray>;
} // namespace vrock::security::hash::SHA2