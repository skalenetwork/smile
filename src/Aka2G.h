#pragma once
#include <vector>

class Aka2G {
public:

    static void compressN(uint8_t *x, int n, const uint8_t *tbl);

    static void  compress(uint8_t *x);

    static void  getBits(uint8_t *x, uint8_t *bits);

    static void  permute(uint8_t *x, uint8_t *bits);

    static void runAka(const uint8_t *ki, const uint8_t *rand, uint8_t *sres, uint8_t *kc);

};
