// src/hmac_sha1.cpp

#include "hmac_sha1.hpp"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdexcept>

std::vector<uint8_t> HmacSha1::calculate(const std::string& key, const std::vector<uint8_t>& data) {
    unsigned char* result;
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<uint8_t> hmac_result(len);
    
    result = HMAC(EVP_sha1(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), hmac_result.data(), &len);
    if (!result) {
        throw std::runtime_error("HMAC-SHA1 calculation failed.");
    }
    hmac_result.resize(len);
    return hmac_result;
}
