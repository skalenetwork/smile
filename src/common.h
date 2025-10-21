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
#include <array>
#include <vector>
#include <tuple>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>




using Block32 = std::array<uint8_t, 4>;
using Block64 = std::array<uint8_t, 8>;
using Block128 = std::array<uint8_t, 16>;
using Block256 = std::array<uint8_t, 32>;

