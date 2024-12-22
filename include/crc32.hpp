// include/crc32.hpp

#ifndef CRC32_HPP
#define CRC32_HPP

#include <vector>
#include <cstdint>

class CRC32 {
public:
    /**
     * @brief Calculates CRC32 for the given data.
     * 
     * @param data The data to calculate CRC32.
     * @return uint32_t The CRC32 checksum.
     */
    static uint32_t calculate(const std::vector<uint8_t>& data);
};

#endif // CRC32_HPP
