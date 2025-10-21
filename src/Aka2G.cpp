//
// Created by kladko on 10/21/25.
//

#include "common.h"
#include "Aka2G.h"
#include "CValues.h"



// -----------------------------------------------------------------------------
// Aka2G::compressN
// -----------------------------------------------------------------------------
// Performs a nonlinear transformation using lookup table `tbl`.
// This function mixes bytes of x[] at different hierarchical levels (n = 0..4).
// -----------------------------------------------------------------------------
void Aka2G::compressN(uint8_t* x, int n, const uint8_t* tbl)
{
    const int secondaryBitCount = 4 - n;
    const int primaryBlockCount = 1 << n;
    const int secondaryBlockCount = 1 << secondaryBitCount;
    const int valueMask = (32 << secondaryBitCount) - 1;

    for (int primaryIndex = 0; primaryIndex < primaryBlockCount; ++primaryIndex) {
        for (int secondaryIndex = 0; secondaryIndex < secondaryBlockCount; ++secondaryIndex) {
            const int lowerIndex = secondaryIndex + primaryIndex * (2 << secondaryBitCount);
            const int upperIndex = lowerIndex + (1 << secondaryBitCount);

            const uint8_t lowerValue = x[lowerIndex];
            const uint8_t upperValue = x[upperIndex];

            const int lowerLookupIndex = (lowerValue + (upperValue << 1)) & valueMask;
            const int upperLookupIndex = ((lowerValue << 1) + upperValue) & valueMask;

            x[lowerIndex] = tbl[lowerLookupIndex];
            x[upperIndex] = tbl[upperLookupIndex];
        }
    }
}

// -----------------------------------------------------------------------------
// Aka2G::compress
// -----------------------------------------------------------------------------
// Runs 5 hierarchical compression levels using precomputed lookup tables.
// -----------------------------------------------------------------------------
void Aka2G::compress(uint8_t* x)
{
    for (int level = 0; level < 5; ++level) {
        compressN(x, level, CValues::values[level]);
    }
}

// -----------------------------------------------------------------------------
// Aka2G::getBits
// -----------------------------------------------------------------------------
// Expands 32 bytes from x[] into 128 bits (as bytes) in bits[].
// Each byte in x contributes 4 bits to the bit array.
// -----------------------------------------------------------------------------
void Aka2G::getBits(uint8_t* x, uint8_t* bits)
{
    std::memset(bits, 0x00, 128);

    for (int bitIndex = 0; bitIndex < 128; ++bitIndex) {
        const int byteIndex = bitIndex >> 2;        // Divide by 4
        const int bitOffset = 3 - (bitIndex & 3);   // Select bit within nibble
        const uint8_t mask = static_cast<uint8_t>(1 << bitOffset);

        if (x[byteIndex] & mask) {
            bits[bitIndex] = 1;
        }
    }
}

// -----------------------------------------------------------------------------
// Aka2G::permute
// -----------------------------------------------------------------------------
// Permutes the 128 extracted bits and reinserts them into the second half
// of x[] (bytes 16–31). This introduces strong bit-level diffusion.
// -----------------------------------------------------------------------------
void Aka2G::permute(uint8_t* x, uint8_t* bits)
{
    std::memset(&x[16], 0x00, 16);

    for (int bitIndex = 0; bitIndex < 128; ++bitIndex) {
        const int byteIndex = (bitIndex >> 3) + 16;        // target byte (x[16..31])
        const int bitOffset = 7 - (bitIndex & 7);          // bit position (7..0)
        const int sourceIndex = (bitIndex * 17) & 127;     // permuted source bit index

        x[byteIndex] |= static_cast<uint8_t>(bits[sourceIndex] << bitOffset);
    }
}

// -----------------------------------------------------------------------------
// Aka2G::runAka
// -----------------------------------------------------------------------------
// Main authentication and key-generation routine (similar to GSM A3/A8).
//
// Inputs:
//   ki   — Subscriber key (16 bytes)
//   rand — Random challenge (16 bytes)
//
// Outputs:
//   sres — 4-byte Signed Response
//   kc   — 8-byte session key
// -----------------------------------------------------------------------------
void Aka2G::runAka(const uint8_t* ki, const uint8_t* rand, uint8_t* sres, uint8_t* kc)
{
    uint8_t x[32] = {0};
    uint8_t bits[128] = {0};

    // Initialize second half of x with RAND
    std::memcpy(&x[16], rand, 16);

    // Perform 7 nonlinear transformation rounds
    for (int round = 0; round < 7; ++round) {
        std::memcpy(x, ki, 16);     // Copy KI into first half
        compress(x);                // Apply compression
        getBits(x, bits);           // Extract bits from x
        permute(x, bits);           // Reinject permuted bits into x
    }

    // Final compression round
    std::memcpy(x, ki, 16);
    compress(x);

    // --- Output stage ---

    // Generate SRES (4 bytes)
    for (int i = 0; i < 8; i += 2) {
        sres[i >> 1] = static_cast<uint8_t>((x[i] << 4) | x[i + 1]);
    }

    // Generate KC (8 bytes)
    for (int i = 0; i < 12; i += 2) {
        kc[i >> 1] = static_cast<uint8_t>(
            (x[i + 18] << 6) |
            (x[i + 19] << 2) |
            (x[i + 20] >> 2)
        );
    }

    kc[6] = static_cast<uint8_t>((x[30] << 6) | (x[31] << 2));
    kc[7] = 0;
}



