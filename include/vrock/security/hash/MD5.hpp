#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::hash::MD5
{
    /// @brief hashes the data using the MD5 algorithm
    /// @param data data to hash
    /// @return hash of the data
    auto hash( const std::shared_ptr<utils::ByteArray> &data ) -> std::shared_ptr<utils::ByteArray>;
} // namespace vrock::security::hash::MD5