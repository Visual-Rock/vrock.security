#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::random
{
    /// @brief generates n random bytes using CryptoPP's NonBlockingRng
    /// @param n amount of bytes to generate
    /// @return random bytes
    auto generate_random_bytes_non_blocking( size_t n ) -> std::shared_ptr<utils::ByteArray>;

    /// @brief generates n random bytes using CryptoPP's RandomPool
    /// @param n amount of bytes to generate
    /// @return random bytes
    auto generate_random_bytes( size_t n ) -> std::shared_ptr<utils::ByteArray>;
} // namespace vrock::security::random