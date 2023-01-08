#include "vrock/security/encryption/RC4.hpp"

#include <iostream>
#include <iomanip>

int main()
{
    auto data = std::make_shared<vrock::utils::ByteArray>("Plaintext");
    auto key = std::make_shared<vrock::utils::ByteArray>("Key");

    auto encrypted = vrock::security::RC4::encrypt(data, key);

    for (int i = 0; i < encrypted->length; ++i)
    {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)encrypted->data[i] << ' ';
    }
    std::cout << std::endl;

    std::cout << vrock::security::RC4::decrypt(encrypted, key)->to_string() << std::endl;
}