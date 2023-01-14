#include "vrock/security/hash/MD5.hpp"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/md5.h"

namespace vrock::security::hash::MD5 {
    std::shared_ptr<utils::ByteArray> hash(std::shared_ptr<utils::ByteArray> data)
    {
        CryptoPP::Weak::MD5 hash;
        auto hashed = std::make_shared<utils::ByteArray>(hash.DigestSize());
        hash.Update(data->data, data->length);
        hash.Final(hashed->data);
        return hashed;
    }
}