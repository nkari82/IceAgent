// include/hmac_sha1.hpp

#ifndef HMAC_SHA1_HPP
#define HMAC_SHA1_HPP

#include <string>
#include <vector>

std::vector<uint8_t> hmac_sha1(const std::string& key, const std::vector<uint8_t>& data);

#endif // HMAC_SHA1_HPP
