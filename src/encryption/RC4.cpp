#include "vrock/security/encryption/RC4.hpp"

#include <iostream>
#include <stdexcept>
#include <utility>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "cryptopp/arc4.h"

namespace vrock::security::encryption::RC4
{
    auto encrypt( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key )
        -> std::shared_ptr<utils::ByteArray>
    {
        CryptoPP::Weak::ARC4 rc4;

        if ( rc4.MaxKeyLength( ) < key->length && rc4.MinKeyLength( ) > key->length )
            throw std::invalid_argument( "the key was of invalid length" );

        rc4.SetKey( key->data, key->length );
        auto encr = std::make_shared<utils::ByteArray>( data->length );

        rc4.ProcessData( encr->data, data->data, data->length );

        return encr;
    }

    auto decrypt( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key )
        -> std::shared_ptr<utils::ByteArray>
    {
        return encrypt( data, key );
    }
} // namespace vrock::security::encryption::RC4