// include/hmac_sha1.hpp

#ifndef HMAC_SHA1_HPP
#define HMAC_SHA1_HPP

#include <vector>
#include <string>
#include <cstdint>

class HmacSha1 {
public:
    static std::vector<uint8_t> calculate(const std::string& key, const std::vector<uint8_t>& data);
};

#endif // HMAC_SHA1_HPP
