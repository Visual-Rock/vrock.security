#include "vrock/security/encryption/RC4.hpp"

#include <iomanip>
#include <iostream>

int main( )
{
    auto data = std::make_shared<vrock::utils::ByteArray>( "Plaintext" );
    auto key = std::make_shared<vrock::utils::ByteArray>( "Key" );

    auto encrypted = vrock::security::encryption::RC4::encrypt( data, key );

    for ( size_t i = 0; i < encrypted->length; ++i )
    {
        std::cout << std::setw( 2 ) << std::setfill( '0' ) << std::hex << (int)encrypted->data[ i ] << ' ';
    }
    std::cout << std::endl;

    std::cout << vrock::security::encryption::RC4::decrypt( encrypted, key )->to_string( ) << std::endl;
}
