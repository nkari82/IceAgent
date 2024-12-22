// include/crc32.hpp

#ifndef CRC32_HPP
#define CRC32_HPP

#include <vector>
#include <string>
#include <array>
#include <cstdint>

class CRC32 {
public:
    static uint32_t calculate(const std::vector<uint8_t>& data);
};

#endif // CRC32_HPP
