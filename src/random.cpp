#include "vrock/security/random.hpp"

#include "cryptopp/osrng.h"
#include "cryptopp/randpool.h"

namespace vrock::security::random {
    std::shared_ptr<utils::ByteArray> generate_random_bytes_non_blocking(size_t n)
    {
        auto data = std::make_shared<utils::ByteArray>(n);
        CryptoPP::NonblockingRng rng;
        rng.GenerateBlock(data->data, n);
        return data;
    }

    std::shared_ptr<utils::ByteArray> generate_random_bytes(size_t n)
    {
        auto data = std::make_shared<utils::ByteArray>(n);
        CryptoPP::RandomPool rng;
        rng.GenerateBlock(data->data, n);
        return data;
    }
}