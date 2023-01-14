#include "vrock/security/encryption/RC4.hpp"

#include <iostream>
#include <stdexcept>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/arc4.h"

namespace vrock::security::encryption::RC4 {
    std::shared_ptr<utils::ByteArray> encrypt(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key)
    {
        CryptoPP::Weak::ARC4 rc4;

        if (rc4.MaxKeyLength() < key->length && rc4.MinKeyLength() > key->length)
            throw std::invalid_argument("the key was of invalid length");

        rc4.SetKey(key->data, key->length);
        auto encr = std::make_shared<utils::ByteArray>(data->length);

        rc4.ProcessData(encr->data, data->data, data->length);

        return encr;
    }

    std::shared_ptr<utils::ByteArray> decrypt(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key)
    {
        return encrypt(data, key);
    }
}