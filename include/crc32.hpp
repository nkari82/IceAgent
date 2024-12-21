// include/crc32.hpp

#ifndef CRC32_HPP
#define CRC32_HPP

#include <cstdint>

uint32_t calculate_crc32(const std::vector<uint8_t>& data);

#endif // CRC32_HPP
