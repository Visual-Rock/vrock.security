#include "vrock/security/encryption/AES.hpp"

#include <string>
#include <vector>

#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <iostream>

namespace vrock::security::AES {

    std::shared_ptr<utils::ByteArray> encrypt_gcm(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key, std::shared_ptr<utils::ByteArray> iv, std::shared_ptr<utils::ByteArray> authentication_data)
    {
        std::string cipher;

        CryptoPP::GCM<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV( key->data, key->length, iv->data, iv->length);
        CryptoPP::AuthenticatedEncryptionFilter ef( e, new CryptoPP::StringSink( cipher ), false, 16);

        ef.ChannelPut("AAD", authentication_data->data, authentication_data->length);
        ef.ChannelMessageEnd("AAD");

        ef.ChannelPut("", data->data, data->length);
        ef.ChannelMessageEnd("");

        return std::make_shared<utils::ByteArray>(cipher);
    }

    std::shared_ptr<utils::ByteArray> decrypt_gcm(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key, std::shared_ptr<utils::ByteArray> iv, std::shared_ptr<utils::ByteArray> authentication_data)
    {
        CryptoPP::GCM<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(key->data, key->length, iv->data, iv->length);
        auto s = data->to_string();
        std::string enc = s.substr(0, s.length() - 16);
        std::string mac = s.substr(s.length() - 16);

        CryptoPP::AuthenticatedDecryptionFilter df(d, nullptr, CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_BEGIN | CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION, 16);

        df.ChannelPut("", (uint8_t*)mac.data(), mac.size());
        df.ChannelPut("AAD", authentication_data->data, authentication_data->length);
        df.ChannelPut("", (uint8_t*)enc.data(), enc.size());

        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );

        auto n = df.MaxRetrievable();
        auto decrypted = std::make_shared<utils::ByteArray>(n);
        if (n > 0)
            df.Get(decrypted->data, n);

        return decrypted;
    }

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

    std::shared_ptr<utils::ByteArray> encrypt_cbc(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key, std::shared_ptr<utils::ByteArray> iv)
    {
        if (iv->length != 16)
            throw std::invalid_argument("initialization vector has to have a length of 16 bytes");

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV(key->data, key->length, iv->data);
        std::string cipher;
        CryptoPP::StringSource s(data->to_string(), true,new CryptoPP::StreamTransformationFilter(e, new CryptoPP::StringSink(cipher)));
        return std::make_shared<utils::ByteArray>(cipher);
    }

    std::shared_ptr<utils::ByteArray> decrypt_cbc(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key, std::shared_ptr<utils::ByteArray> iv)
    {
        if (iv->length != 16)
            throw std::invalid_argument("initialization vector has to have a length of 16 bytes");

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(key->data, key->length, iv->data);

        std::string decrypted;

        CryptoPP::StringSource s(data->to_string(), true, new CryptoPP::StreamTransformationFilter(d, new CryptoPP::StringSink(decrypted) ) );

        return std::make_shared<utils::ByteArray>(decrypted);
    }
}