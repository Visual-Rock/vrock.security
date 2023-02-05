#include "vrock/security/random.hpp"

#include <iostream>
#include <iomanip>

int main()
{
    auto bytes = vrock::security::random::generate_random_bytes(16);

    for (size_t i = 0; i < bytes->length; ++i)
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)bytes->data[i] << ' ';
    std::cout << std::endl;

    return 0;
}