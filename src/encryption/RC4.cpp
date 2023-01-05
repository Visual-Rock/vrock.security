#include "vrock/security/encryption/RC4.hpp"

#include <cassert>
#include <iostream>

namespace vrock::security::RC4 {
    void swap(std::shared_ptr<utils::ByteArray> data, size_t i, size_t j)
    {
        uint8_t tmp = data->data[i];
        data->data[i] = data->data[j];
        data->data[j] = tmp;
    }

    std::shared_ptr<utils::ByteArray> encrypt(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key)
    {
        // generate S-Box
        auto s = std::make_shared<utils::ByteArray>(256);
        {
            for (size_t i = 0; i < 256; ++i)
                s->set(i, i);

            size_t j = 0;
            for (size_t i = 0; i < 256; ++i) {
                j = (j + s->get(i) + key->get(i % key->length)) % 256;
                swap(s, i, j);
            }
        }

        auto cypher = std::make_shared<utils::ByteArray>(data->length);

        size_t i = 0; size_t j = 0;
        uint8_t num;
        for (size_t n = 0; n < data->length; ++n)
        {
            i = (i + 1) % 256;
            j = (j + s->get(i)) % 256;
            swap(s, i, j);
            num = s->get((s->get(i) + s->get(j)) % 256);
            cypher->set(n, num ^ data->get(n));
        }

        return cypher;
    }

    std::shared_ptr<utils::ByteArray> decrypt(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key)
    {
        return encrypt(data, key);
    }
}