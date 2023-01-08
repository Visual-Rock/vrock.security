#include "vrock/security/encryption/AES.hpp"

#include <string>
#include <vector>

#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include <cryptopp/filters.h>
#include <iostream>

namespace vrock::security::AES {

    std::shared_ptr<utils::ByteArray> encrypt_ecb(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key)
    {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
        e.SetKey(key->data, key->length);
        std::string cypher;
        CryptoPP::StringSource(data->to_string(), true, new CryptoPP::StreamTransformationFilter(e, new CryptoPP::StringSink(cypher)));

        return std::make_shared<utils::ByteArray>(cypher);
    }

    std::shared_ptr<utils::ByteArray> decrypt_ecb(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key)
    {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
        d.SetKey(key->data, key->length);
        std::string decrypted;

        CryptoPP::StringSource s(data->to_string(), true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(decrypted)));

        return std::make_shared<utils::ByteArray>(decrypted);
    }
}