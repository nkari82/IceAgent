// src/crc32.cpp

#include "crc32.hpp"

uint32_t CRC32::calculate(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for(auto byte : data) {
        crc ^= byte;
        for(int i = 0; i < 8; ++i) {
            if(crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>=1;
        }
    }
    return crc ^ 0xFFFFFFFF;
}
