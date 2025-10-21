//#pragma once
#include <vector>
#include <string>

std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt,
                                        const std::vector<uint8_t>& ikm);

std::vector<uint8_t> hkdf_expand(const std::vector<uint8_t>& prk,
                                       const std::string& info,
                                       size_t L);