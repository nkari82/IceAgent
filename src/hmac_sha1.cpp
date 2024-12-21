// src/hmac_sha1.cpp

#include "hmac_sha1.hpp"
#include <cstdint>
#include <cstring>

// 간단한 SHA1 구현을 사용합니다. 실제 구현은 복잡하므로 여기서는 외부 라이브러리를 사용하지 않고 간략화합니다.
// 이는 교육용 예제일 뿐이며, 실제 사용 시 검증된 라이브러리를 사용해야 합니다.

// SHA1 클래스는 구현되지 않았으므로, 이 예제에서는 빈 벡터를 반환합니다.
// 실제로는 SHA1 해시 함수를 구현해야 합니다.
std::vector<uint8_t> sha1(const std::vector<uint8_t>& data) {
    // SHA1 구현 필요
    // Placeholder: 실제 SHA1 해시를 반환해야 합니다.
    return std::vector<uint8_t>(20, 0); // 20바이트 SHA1 해시
}

std::vector<uint8_t> hmac_sha1(const std::string& key, const std::vector<uint8_t>& data) {
    const size_t BLOCK_SIZE = 64; // SHA1 블록 크기
    std::vector<uint8_t> key_bytes(key.begin(), key.end());

    if (key_bytes.size() > BLOCK_SIZE) {
        key_bytes = sha1(key_bytes);
    }

    if (key_bytes.size() < BLOCK_SIZE) {
        key_bytes.resize(BLOCK_SIZE, 0x00);
    }

    std::vector<uint8_t> o_key_pad(BLOCK_SIZE, 0x5c);
    std::vector<uint8_t> i_key_pad(BLOCK_SIZE, 0x36);

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        o_key_pad[i] ^= key_bytes[i];
        i_key_pad[i] ^= key_bytes[i];
    }

    std::vector<uint8_t> inner_data = i_key_pad;
    inner_data.insert(inner_data.end(), data.begin(), data.end());

    std::vector<uint8_t> inner_hash = sha1(inner_data);

    std::vector<uint8_t> outer_data = o_key_pad;
    outer_data.insert(outer_data.end(), inner_hash.begin(), inner_hash.end());

    std::vector<uint8_t> hmac = sha1(outer_data);

    return hmac;
}