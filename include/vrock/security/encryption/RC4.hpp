#pragma once

#include "vrock/utils/ByteArray.hpp"

namespace vrock::security::RC4 {
    std::shared_ptr<utils::ByteArray> encrypt(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key);
    std::shared_ptr<utils::ByteArray> decrypt(std::shared_ptr<utils::ByteArray> data, std::shared_ptr<utils::ByteArray> key);
}