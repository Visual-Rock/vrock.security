#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::hash::MD5 {
    /// @brief hashes the data using the MD5 algorithm
    /// @param data data to hash
    /// @return hash of the data
    std::shared_ptr<utils::ByteArray> hash(std::shared_ptr<utils::ByteArray> data);
}