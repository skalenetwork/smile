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

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

/**
 * @file common.h
 * @brief Common includes and fixed-size byte array aliases used across the project.
 */

/** 2-byte array alias. */
using array2 = std::array<uint8_t, 2>;
/** 4-byte array alias. */
using array4 = std::array<uint8_t, 4>;
/** 8-byte array alias. */
using array8 = std::array<uint8_t, 8>;
/** 16-byte array alias. */
using array16 = std::array<uint8_t, 16>;
/** 32-byte array alias (often used for keys/seeds). */
using array32 = std::array<uint8_t, 32>;
/** 33-byte array alias (compressed EC public key). */
using array33 = std::array<uint8_t, 33>;

