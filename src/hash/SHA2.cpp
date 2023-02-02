#include "vrock/security/hash/SHA2.hpp"

#include <cryptopp/sha.h>

namespace vrock::security::hash::SHA2
{
    std::shared_ptr<utils::ByteArray> sha224(std::shared_ptr<utils::ByteArray> data)
    {
        CryptoPP::SHA224 hash;
        auto hashed = std::make_shared<utils::ByteArray>(hash.DigestSize());
        hash.Update(data->data, data->length);
        hash.Final(hashed->data);
        return hashed;
    }

    std::shared_ptr<utils::ByteArray> sha256(std::shared_ptr<utils::ByteArray> data)
    {
        CryptoPP::SHA256 hash;
        auto hashed = std::make_shared<utils::ByteArray>(hash.DigestSize());
        hash.Update(data->data, data->length);
        hash.Final(hashed->data);
        return hashed;
    }

    std::shared_ptr<utils::ByteArray> sha384(std::shared_ptr<utils::ByteArray> data)
    {
        CryptoPP::SHA384 hash;
        auto hashed = std::make_shared<utils::ByteArray>(hash.DigestSize());
        hash.Update(data->data, data->length);
        hash.Final(hashed->data);
        return hashed;
    }

    std::shared_ptr<utils::ByteArray> sha512(std::shared_ptr<utils::ByteArray> data)
    {
        CryptoPP::SHA512 hash;
        auto hashed = std::make_shared<utils::ByteArray>(hash.DigestSize());
        hash.Update(data->data, data->length);
        hash.Final(hashed->data);
        return hashed;
    }
}