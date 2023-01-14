#include "vrock/security/hash/MD5.hpp"

#include <iostream>
#include <iomanip>

int main()
{
    auto data = vrock::utils::ByteArray::from_string("Test");
    std::cout << "hash: " << vrock::security::hash::MD5::hash(data)->to_hex_string() << std::endl << "ref:  0cbc6611f5540bd0809a388dc95a615b" << std::endl;
}