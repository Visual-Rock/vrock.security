#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::hash::SHA2 {
    /// @brief hashes the data using the sha-224 algorithm 
    /// @param data data to hash
    /// @return hash of the data
    std::shared_ptr<utils::ByteArray> sha224(std::shared_ptr<utils::ByteArray> data);

    /// @brief hashes the data using the sha-256 algorithm 
    /// @param data data to hash
    /// @return hash of the data
    std::shared_ptr<utils::ByteArray> sha256(std::shared_ptr<utils::ByteArray> data);

    /// @brief hashes the data using the sha-384 algorithm 
    /// @param data data to hash
    /// @return hash of the data
    std::shared_ptr<utils::ByteArray> sha384(std::shared_ptr<utils::ByteArray> data);

    /// @brief hashes the data using the sha-512 algorithm 
    /// @param data data to hash
    /// @return hash of the data
    std::shared_ptr<utils::ByteArray> sha512(std::shared_ptr<utils::ByteArray> data);
}