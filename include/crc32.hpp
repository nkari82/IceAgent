// include/crc32.hpp

#ifndef CRC32_HPP
#define CRC32_HPP

#include <vector>
#include <string>
#include <array>
#include <cstdint>

class CRC32
{
public:
    static uint32_t calculate(const std::vector<uint8_t> &data)
    {
        static const std::array<uint32_t, 256> crc_table = []
        {
            std::array<uint32_t, 256> table = {};
            for (uint32_t i = 0; i < 256; ++i)
            {
                uint32_t crc = i;
                for (uint32_t j = 0; j < 8; ++j)
                {
                    crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
                }
                table[i] = crc;
            }
            return table;
        }();

        uint32_t crc = 0xFFFFFFFF;
        for (uint8_t byte : data)
        {
            crc = (crc >> 8) ^ crc_table[(crc ^ byte) & 0xFF];
        }

        return ~crc;
    }
};

#endif // CRC32_HPP
