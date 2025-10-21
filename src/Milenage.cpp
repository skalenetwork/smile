#include "common.h"
#include "Milenage.h"
#include <openssl/evp.h>
#include <cstring>
#include <cassert>



// Rotate left a 128-bit block by ‘bits’ bits
static void rol128(const array16 &in, int bits, array16 &out) {
    assert(bits >= 0 && bits < 128);
    int byteShift = bits / 8;
    int bitShift  = bits % 8;

    for (int i = 0; i < 16; ++i) {
        uint16_t w = uint16_t(in[(i + byteShift) % 16]) << 8;
        if (byteShift + 1 < 16) {
            w |= in[(i + byteShift + 1) % 16];
        } else {
            w |= in[( (i + byteShift + 1) % 16 )];
        }
        out[i] = uint8_t((w >> (8 - bitShift)) & 0xFF);
    }
}

// AES encrypt a single 128-bit block with key K
static void aes128_ecb(const array16 &K, const array16 &in, array16 &out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    assert(ctx != nullptr);
    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, K.data(), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_EncryptUpdate   (ctx, out.data(), &len, in.data(), 16);
    EVP_EncryptFinal_ex (ctx, nullptr, &len);
    EVP_CIPHER_CTX_free(ctx);
}

// XOR two 128-bit blocks
static void xor128(const array16 &a, const array16 &b, array16 &out) {
    for (int i = 0; i < 16; ++i) {
        out[i] = a[i] ^ b[i];
    }
}

void deriveOpc(const array16 &K, const array16 &OP, array16 &OPc) {
    array16 tmp;
    aes128_ecb(K, OP, tmp);
    xor128(tmp, OP, OPc);
}

void f1(const array16 &K, const array16 &RAND,
        const array16 &SQN, const array16 &AMF,
        const array16 &OPc,
        std::array<uint8_t, 8> &MAC_A, std::array<uint8_t, 8> &MAC_S)
{
    static const int r1 = 64;
    static const int r1star = 64; // often same as r1, spec may allow different
    array16 temp, in1, out1;

    xor128(RAND, OPc, temp);
    aes128_ecb(K, temp, out1);

    // in1 = SQN || AMF || SQN || AMF
    std::memcpy(in1.data(),       SQN.data(),  6);
    std::memcpy(in1.data()+6,     AMF.data(),  2);
    std::memcpy(in1.data()+8,     SQN.data(),  6);
    std::memcpy(in1.data()+14,    AMF.data(),  2);

    xor128(out1, OPc, temp);
    rol128(temp, r1, temp);
    aes128_ecb(K, temp, out1);
    for (int i = 0; i < 8; ++i) MAC_A[i] = out1[i];

    // compute MAC_S
    xor128(out1, OPc, temp);
    rol128(temp, r1star, temp);
    aes128_ecb(K, temp, out1);
    for (int i = 0; i < 8; ++i) MAC_S[i] = out1[i];
}

void f2345(const array16 &K, const array16 &RAND, const array16 &OPc,
           std::array<uint8_t, 8> &RES,
           array16 &CK, array16 &IK,
           std::array<uint8_t, 6> &AK, std::array<uint8_t, 6> &AKstar)
{
    static const int r2 = 0;
    static const int r3 = 32;
    static const int r4 = 64;
    static const int r5 = 96;

    array16 temp, out2, in2;

    xor128(RAND, OPc, temp);
    aes128_ecb(K, temp, out2);

    // f2 → RES and AK
    xor128(out2, OPc, temp);
    rol128(temp, r2, temp);
    // XOR with c2
    temp[15] ^= 0x02;
    aes128_ecb(K, temp, in2);
    for (int i = 0; i < 8; ++i) RES[i] = in2[i + 8];
    for (int i = 0; i < 6; ++i) AK[i]  = in2[i];

    // f3 → CK
    xor128(out2, OPc, temp);
    rol128(temp, r3, temp);
    temp[15] ^= 0x04;
    aes128_ecb(K, temp, CK);

    // f4 → IK
    xor128(out2, OPc, temp);
    rol128(temp, r4, temp);
    temp[15] ^= 0x08;
    aes128_ecb(K, temp, IK);

    // f5 → AK*
    xor128(out2, OPc, temp);
    rol128(temp, r5, temp);
    temp[15] ^= 0x10;
    aes128_ecb(K, temp, in2);
    for (int i = 0; i < 6; ++i) AKstar[i] = in2[i];
}

