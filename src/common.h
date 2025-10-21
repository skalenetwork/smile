#pragma once

#include <array>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

using Block32 = std::array<uint8_t, 4>;
using Block64 = std::array<uint8_t, 8>;
using Block128 = std::array<uint8_t, 16>;
using Block256 = std::array<uint8_t, 32>;

