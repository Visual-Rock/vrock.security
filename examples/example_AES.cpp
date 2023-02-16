#include "vrock/security/encryption/AES.hpp"

#include <iomanip>
#include <iostream>

int main( )
{
    auto data = vrock::utils::ByteArray::from_hex_string( "00000000000000000000000000000000" );
    auto key = vrock::utils::ByteArray::from_hex_string(
        "0000000000000000000000000000000000000000000000000000000000000000" ); // Keys have to be either 128, 192, or 256
                                                                              // bit long
    auto iv = vrock::utils::ByteArray::from_hex_string( "000000000000000000000000" ); // 12 byte long
    auto aad = vrock::utils::ByteArray::from_hex_string( "00000000000000000000000000000000" );
    auto expected = vrock::utils::ByteArray::from_hex_string( "c0749a1e19196e977506c0e2f1af6f4552" );
    auto encrypted = vrock::security::encryption::AES::encrypt_gcm( data, key, iv, aad );

    for ( size_t i = 0; i < encrypted->length; ++i )
        std::cout << std::setw( 2 ) << std::setfill( '0' ) << std::hex << (int)encrypted->data[ i ] << ' ';
    std::cout << std::endl;
    for ( size_t i = 0; i < expected->length; ++i )
        std::cout << std::setw( 2 ) << std::setfill( '0' ) << std::hex << (int)expected->data[ i ] << ' ';
    auto decrypted = vrock::security::encryption::AES::decrypt_gcm( encrypted, key, iv, aad );
    std::cout << std::endl << decrypted->to_string( ) << std::endl;
}