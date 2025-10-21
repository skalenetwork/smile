#include "kdf.h"
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <stdexcept>

std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt,
                                        const std::vector<uint8_t>& ikm) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    std::vector<uint8_t> prk(32);
    size_t prk_len = prk.size();
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm.data(), ikm.size()) <= 0 ||
        EVP_PKEY_derive(pctx, prk.data(), &prk_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF-Extract failed");
        }

    EVP_PKEY_CTX_free(pctx);
    return prk;
}

std::vector<uint8_t> hkdf_expand(const std::vector<uint8_t>& prk,
                                       const std::string& info,
                                       size_t L) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    std::vector<uint8_t> out(L);
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, prk.data(), prk.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>(info.data()), info.size()) <= 0 ||
        EVP_PKEY_derive(pctx, out.data(), &L) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF-Expand failed");
        }

    EVP_PKEY_CTX_free(pctx);
    return out;
}