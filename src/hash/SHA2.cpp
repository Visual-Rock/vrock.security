#include "vrock/security/hash/SHA2.hpp"

#include <cryptopp/sha.h>

namespace vrock::security::hash::SHA2
{
    auto sha224( const std::shared_ptr<utils::ByteArray> &data ) -> std::shared_ptr<utils::ByteArray>
    {
        CryptoPP::SHA224 hash;
        auto hashed = std::make_shared<utils::ByteArray>( hash.DigestSize( ) );
        hash.Update( data->data, data->length );
        hash.Final( hashed->data );
        return hashed;
    }

    auto sha256( const std::shared_ptr<utils::ByteArray> &data ) -> std::shared_ptr<utils::ByteArray>
    {
        CryptoPP::SHA256 hash;
        auto hashed = std::make_shared<utils::ByteArray>( hash.DigestSize( ) );
        hash.Update( data->data, data->length );
        hash.Final( hashed->data );
        return hashed;
    }

    auto sha384( const std::shared_ptr<utils::ByteArray> &data ) -> std::shared_ptr<utils::ByteArray>
    {
        CryptoPP::SHA384 hash;
        auto hashed = std::make_shared<utils::ByteArray>( hash.DigestSize( ) );
        hash.Update( data->data, data->length );
        hash.Final( hashed->data );
        return hashed;
    }

    auto sha512( const std::shared_ptr<utils::ByteArray> &data ) -> std::shared_ptr<utils::ByteArray>
    {
        CryptoPP::SHA512 hash;
        auto hashed = std::make_shared<utils::ByteArray>( hash.DigestSize( ) );
        hash.Update( data->data, data->length );
        hash.Final( hashed->data );
        return hashed;
    }
} // namespace vrock::security::hash::SHA2