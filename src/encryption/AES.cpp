#include "vrock/security/encryption/AES.hpp"

#include <string>
#include <vector>

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/modes.h>
#include <iostream>

namespace vrock::security::encryption::AES
{
    auto convert_padding_scheme( Padding padding ) -> CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme
    {
        switch ( padding )
        {
        case NO_PADDING:
            return CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING;
        case Padding::ZEROS_PADDING:
            return CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ZEROS_PADDING;
        case Padding::ONE_AND_ZEROS_PADDING:
            return CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::ONE_AND_ZEROS_PADDING;
        case Padding::PKCS_PADDING:
            return CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::PKCS_PADDING;
        case Padding::W3C_PADDING:
            return CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::W3C_PADDING;
        default:
            return CryptoPP::BlockPaddingSchemeDef::BlockPaddingScheme::NO_PADDING;
        }
    }

    auto encrypt_gcm( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      const std::shared_ptr<utils::ByteArray> &iv,
                      const std::shared_ptr<utils::ByteArray> &authentication_data )
        -> std::shared_ptr<utils::ByteArray>
    {
        std::string cipher;

        CryptoPP::GCM<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV( key->data, key->length, iv->data, iv->length );
        CryptoPP::AuthenticatedEncryptionFilter ef( e, new CryptoPP::StringSink( cipher ), false, 16 );

        ef.ChannelPut( "AAD", authentication_data->data, authentication_data->length );
        ef.ChannelMessageEnd( "AAD" );

        ef.ChannelPut( "", data->data, data->length );
        ef.ChannelMessageEnd( "" );

        return std::make_shared<utils::ByteArray>( cipher );
    }

    auto decrypt_gcm( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      const std::shared_ptr<utils::ByteArray> &iv,
                      const std::shared_ptr<utils::ByteArray> &authentication_data )
        -> std::shared_ptr<utils::ByteArray>
    {
        CryptoPP::GCM<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV( key->data, key->length, iv->data, iv->length );
        auto s = data->to_string( );
        std::string enc = s.substr( 0, s.length( ) - 16 );
        std::string mac = s.substr( s.length( ) - 16 );

        CryptoPP::AuthenticatedDecryptionFilter df( d, nullptr,
                                                    CryptoPP::AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                                        CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                                    16 );

        df.ChannelPut( "", (uint8_t *)mac.data( ), mac.size( ) );
        df.ChannelPut( "AAD", authentication_data->data, authentication_data->length );
        df.ChannelPut( "", (uint8_t *)enc.data( ), enc.size( ) );

        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );

        auto n = df.MaxRetrievable( );
        auto decrypted = std::make_shared<utils::ByteArray>( n );
        if ( n > 0 )
            df.Get( decrypted->data, n );

        return decrypted;
    }

    auto encrypt_ecb( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      Padding padding ) -> std::shared_ptr<utils::ByteArray>
    {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
        e.SetKey( key->data, key->length );
        std::string cypher;
        CryptoPP::StringSource c( data->to_string( ), true,
                                  new CryptoPP::StreamTransformationFilter( e, new CryptoPP::StringSink( cypher ),
                                                                            convert_padding_scheme( padding ) ) );

        return std::make_shared<utils::ByteArray>( cypher );
    }

    auto decrypt_ecb( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      Padding padding ) -> std::shared_ptr<utils::ByteArray>
    {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
        d.SetKey( key->data, key->length );
        std::string decrypted;

        CryptoPP::StringSource s( data->to_string( ), true,
                                  new CryptoPP::StreamTransformationFilter( d, new CryptoPP::StringSink( decrypted ),
                                                                            convert_padding_scheme( padding ) ) );

        return std::make_shared<utils::ByteArray>( decrypted );
    }

    auto encrypt_cbc( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      const std::shared_ptr<utils::ByteArray> &iv, Padding padding )
        -> std::shared_ptr<utils::ByteArray>
    {
        if ( iv->length != 16 )
            throw std::invalid_argument( "initialization vector has to have a length of 16 bytes" );

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV( key->data, key->length, iv->data );
        std::string cipher;
        CryptoPP::StringSource s( data->to_string( ), true,
                                  new CryptoPP::StreamTransformationFilter( e, new CryptoPP::StringSink( cipher ),
                                                                            convert_padding_scheme( padding ) ) );
        return std::make_shared<utils::ByteArray>( cipher );
    }

    auto decrypt_cbc( const std::shared_ptr<utils::ByteArray> &data, const std::shared_ptr<utils::ByteArray> &key,
                      const std::shared_ptr<utils::ByteArray> &iv, Padding padding )
        -> std::shared_ptr<utils::ByteArray>
    {
        if ( iv->length != 16 )
            throw std::invalid_argument( "initialization vector has to have a length of 16 bytes" );

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV( key->data, key->length, iv->data );

        std::string decrypted;

        CryptoPP::StringSource s( data->to_string( ), true,
                                  new CryptoPP::StreamTransformationFilter( d, new CryptoPP::StringSink( decrypted ),
                                                                            convert_padding_scheme( padding ) ) );

        return std::make_shared<utils::ByteArray>( decrypted );
    }
} // namespace vrock::security::encryption::AES