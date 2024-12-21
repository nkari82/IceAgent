// src/crc32.cpp

#include "crc32.hpp"

// 표준 CRC32 테이블 생성
static uint32_t crc_table[256];

static bool table_computed = false;

void compute_crc_table() {
    uint32_t c;
    for (uint32_t n = 0; n < 256; n++) {
        c = n;
        for (size_t k = 0; k < 8; k++) {
            if (c & 1)
                c = 0xEDB88320L ^ (c >> 1);
            else
                c = c >> 1;
        }
        crc_table[n] = c;
    }
    table_computed = true;
}

uint32_t calculate_crc32(const std::vector<uint8_t>& data) {
    if (!table_computed) {
        compute_crc_table();
    }
    uint32_t crc = 0xFFFFFFFF;
    for (auto byte : data) {
        crc = crc_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}
