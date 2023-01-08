#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::AES {
    std::shared_ptr<utils::ByteArray> encrypt_ecb(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key);
    std::shared_ptr<utils::ByteArray> decrypt_ecb(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key);
}