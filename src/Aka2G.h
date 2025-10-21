#pragma once
#include <vector>

/**
 * @brief Utility class implementing a simplified COMP128-1 based 2G AKA flow.
 *
 * The functions operate on 128-bit internal state arrays and helper bit buffers
 * to emulate the historical A3/A8 behavior for educational/testing purposes.
 */
class Aka2G {
public:
    /**
     * @brief One stage of COMP128-1 compression using a level-specific table.
     * @param x    128-byte working buffer (modified in place).
     * @param n    Compression level (0..4) determining block sizes.
     * @param tbl  Pointer to the lookup table for this stage.
     */
    static void compressN(uint8_t *x, int n, const uint8_t *tbl);

    /**
     * @brief Performs all COMP128-1 compression rounds over the working buffer.
     * @param x 128-byte working buffer (modified in place).
     */
    static void  compress(uint8_t *x);

    /**
     * @brief Extracts bit representation from the internal state for permutation.
     * @param x    128-byte working buffer.
     * @param bits Output 128-byte bit array (each byte contains a single bit value 0/1).
     */
    static void  getBits(uint8_t *x, uint8_t *bits);

    /**
     * @brief Applies the COMP128-1 permutation to the internal state using bits.
     * @param x    128-byte working buffer (modified in place).
     * @param bits 128-byte bit array prepared by getBits().
     */
    static void  permute(uint8_t *x, uint8_t *bits);

    /**
     * @brief Runs the 2G AKA (A3/A8) to compute SRES and Kc from Ki and RAND.
     * @param ki   16-byte subscriber key Ki.
     * @param rand 16-byte random challenge RAND.
     * @param sres Output 4-byte Signed Response.
     * @param kc   Output 8-byte ciphering key Kc.
     */
    static void runAka(const uint8_t *ki, const uint8_t *rand, uint8_t *sres, uint8_t *kc);

};
