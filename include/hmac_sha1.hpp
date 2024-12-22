// include/hmac_sha1.hpp

#ifndef HMAC_SHA1_HPP
#define HMAC_SHA1_HPP

#include <vector>
#include <cstdint>
#include <string>

class HmacSha1 {
public:
    /**
     * @brief Calculates HMAC-SHA1 for the given key and data.
     * 
     * @param key The secret key.
     * @param data The data to hash.
     * @return std::vector<uint8_t> The HMAC-SHA1 result.
     */
    static std::vector<uint8_t> calculate(const std::string& key, const std::vector<uint8_t>& data);
};

#endif // HMAC_SHA1_HPP
