#include "vrock/security/encryption/AES.hpp"

#include <iostream>
#include <iomanip>

int main()
{
    auto data = vrock::utils::ByteArray::from_string("Plaintext");
    auto key = vrock::utils::ByteArray::from_string("KeyKeyKeyKeyKeyK"); // Keys have to be either 128, 192, or 256 bit long
    auto encrypted = vrock::security::AES::encrypt_ecb(data, key);

    for (int i = 0; i < encrypted->length; ++i)
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)encrypted->data[i] << ' ';

    std::cout << std::endl << vrock::security::AES::decrypt_ecb(encrypted, key)->to_string() << std::endl;
}