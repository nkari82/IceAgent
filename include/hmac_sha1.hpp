// include/hmac_sha1.hpp

#ifndef HMAC_SHA1_HPP
#define HMAC_SHA1_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// OpenSSL 헤더 포함 조건부
#if __has_include(<openssl/hmac.h>)
#include <openssl/hmac.h>
#include <openssl/sha.h>
#endif

// Include headers based on platform and available features
#ifdef defined(_WIN32) || defined(__linux__)
#if __has_include(<cpuid.h>)
#include <cpuid.h>
#endif
#if __has_include(<intrin.h>)
#include <intrin.h>
#endif
#if __has_include(<immintrin.h>)
#include <immintrin.h>  // For AVX/AVX2
#endif
#if __has_include(<nmmintrin.h>)
#include <nmmintrin.h>  // For SSE4.2
#endif
#if __has_include(<emmintrin.h>)
#include <emmintrin.h>  // For SSE2
#endif
#endif

#ifdef defined(__ANDROID__)
#if __has_include(<arm_neon.h>)
#include <arm_neon.h>  // For NEON
#endif
#endif

#ifdef defined(__APPLE__)
#if __has_include(<TargetConditionals.h>)
#include <TargetConditionals.h>  // For detecting Apple platforms
#endif
#if TARGET_OS_IPHONE || TARGET_OS_SIMULATOR
#if __has_include(<arm_neon.h>)
#include <arm_neon.h>  // For NEON
#endif
#elif TARGET_OS_MAC
#if __has_include(<immintrin.h>)
#include <immintrin.h>  // For AVX/AVX2
#endif
#if __has_include(<nmmintrin.h>)
#include <nmmintrin.h>  // For SSE4.2
#endif
#if __has_include(<emmintrin.h>)
#include <emmintrin.h>  // For SSE2
#endif
#endif
#endif

class HmacSha1 {
   public:
#if __has_include(<openssl/hmac.h>)
    // OpenSSL을 사용하는 HMAC-SHA1 계산 함수
    static std::vector<uint8_t> calculate(const std::string &key, const std::vector<uint8_t> &data) {
        const unsigned char *key_ptr = reinterpret_cast<const unsigned char *>(key.data());
        const unsigned char *data_ptr = data.data();

        unsigned char result[EVP_MAX_MD_SIZE];
        unsigned int result_len = 0;

        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create HMAC context");
        }

        if (!HMAC_Init_ex(ctx, key_ptr, static_cast<int>(key.size()), EVP_sha1(), nullptr)) {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize HMAC context");
        }

        if (!HMAC_Update(ctx, data_ptr, data.size())) {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("Failed to update HMAC");
        }

        if (!HMAC_Final(ctx, result, &result_len)) {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize HMAC");
        }

        HMAC_CTX_free(ctx);

        return std::vector<uint8_t>(result, result + result_len);
    }
#else
    // OpenSSL을 사용하지 않는 경우, 커스텀 HMAC-SHA1 구현
    static std::vector<uint8_t> calculate(const std::string &key, const std::vector<uint8_t> &data) {
        static auto hmac_func = select_hmac_function();
        return hmac_func(key, data);
    }

   private:
    using HMACFunction = std::vector<uint8_t> (*)(const std::string &, const std::vector<uint8_t> &);

    enum class FeatureIndex : int { NONE = -1, ARM_CRC32, NEON, AVX2, AVX, SSE42, SSE2 };

    // 지원되는 인스트럭션셋 감지
    static FeatureIndex detect_supported_feature() {
#if defined(__ANDROID__) || (defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR))
        return FeatureIndex::NEON;
#elif defined(_WIN32) || defined(__linux__)  // x86
        unsigned int reg[4]{0};
#if __has_include(<intrin.h>)
        __cpuid((int *)reg, 1);
#elif defined(__GNUC__) || defined(__clang__)
        __get_cpuid(1, &reg[0], &reg[1], &reg[2], &reg[3]);
#endif
        if ((reg[2] & (1 << 28)) != 0)
            return FeatureIndex::AVX;
        if ((reg[2] & (1 << 20)) != 0)
            return FeatureIndex::SSE42;
        if ((reg[3] & (1 << 26)) != 0)
            return FeatureIndex::SSE2;

#if __has_include(<intrin.h>)
        __cpuid((int *)reg, 7);
#elif defined(__GNUC__) || defined(__clang__)
        __get_cpuid(7, &reg[0], &reg[1], &reg[2], &reg[3]);
#endif
        if ((reg[1] & (1 << 5)) != 0)
            return FeatureIndex::AVX2;
#endif
        return FeatureIndex::NONE;
    }

    // 최적화된 HMAC 함수 선택
    static HMACFunction select_hmac_function() {
        switch (detect_supported_feature()) {
#if __has_include(<immintrin.h>)
            case FeatureIndex::AVX:
                return hmac_avx;
            case FeatureIndex::AVX2:
                return hmac_avx2;
#endif
#if __has_include(<emmintrin.h>)
            case FeatureIndex::SSE2:
                return hmac_sse2;
#endif
#if __has_include(<nmmintrin.h>)
            case FeatureIndex::SSE42:
                return hmac_sse42;
#endif
#if defined(__ANDROID__) || (defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR))
            case FeatureIndex::NEON:
                return hmac_neon;
#endif
            default:
                return hmac_generic;
        }
    }

    // 공통 HMAC-SHA1 구현
    static std::vector<uint8_t> hmac_common(const std::string &key, const std::vector<uint8_t> &data,
                                            std::vector<uint8_t> (*sha1_func)(const uint8_t *data, size_t size)) {
        const size_t block_size = 64;
        std::vector<uint8_t> key_pad(block_size, 0);
        if (key.size() > block_size) {
            std::vector<uint8_t> hashed_key = sha1_func(reinterpret_cast<const uint8_t *>(key.data()), key.size());
            std::copy(hashed_key.begin(), hashed_key.end(), key_pad.begin());
        } else {
            std::copy(key.begin(), key.end(), key_pad.begin());
        }

        std::vector<uint8_t> o_key_pad(block_size, 0x5c);
        std::vector<uint8_t> i_key_pad(block_size, 0x36);
        for (size_t i = 0; i < block_size; ++i) {
            o_key_pad[i] ^= key_pad[i];
            i_key_pad[i] ^= key_pad[i];
        }

        auto combined = [&](const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
            std::vector<uint8_t> combined(size1 + size2);
            std::memcpy(combined.data(), data1, size1);
            std::memcpy(combined.data() + size1, data2, size2);
            return sha1_func(combined.data(), combined.size());
        };

        std::vector<uint8_t> inner_hash =
            combined(i_key_pad.data(), i_key_pad.size() + data.size(), data.data(), data.size());
        std::vector<uint8_t> result =
            combined(o_key_pad.data(), o_key_pad.size() + inner_hash.size(), inner_hash.data(), inner_hash.size());
        return result;
    }

    static std::vector<uint8_t> hmac_generic(const std::string &key, const std::vector<uint8_t> &data) {
        return hmac_common(key, data, &SHA1::sha1_generic);
    }

#if __has_include(<immintrin.h>)
    static std::vector<uint8_t> hmac_avx(const std::string &key, const std::vector<uint8_t> &data) {
        return hmac_common(key, data, &SHA1::sha1_avx);
    }

    static std::vector<uint8_t> hmac_avx2(const std::string &key, const std::vector<uint8_t> &data) {
        return hmac_common(key, data, &SHA1::sha1_avx2);
    }
#endif

#if __has_include(<nmmintrin.h>)
    static std::vector<uint8_t> hmac_sse42(const std::string &key, const std::vector<uint8_t> &data) {
        return hmac_common(key, data, &SHA1::sha1_sse42);
    }
#endif

#if __has_include(<emmintrin.h>)
    static std::vector<uint8_t> hmac_sse2(const std::string &key, const std::vector<uint8_t> &data) {
        return hmac_common(key, data, &SHA1::sha1_sse2);
    }
#endif

// NEON 최적화된 HMAC-SHA1 구현
#if defined(__ANDROID__) || (defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR))
    static std::vector<uint8_t> hmac_neon(const std::string &key, const std::vector<uint8_t> &data) {
        return hmac_common(key, data, &SHA1::sha1_neon);
    }
#endif

    // 커스텀 SHA1 구현
    class SHA1 {
       public:
        // 기본 SHA1 구현 (비최적화)
        static std::vector<uint8_t> sha1_generic(const uint8_t *data, size_t size) {
            std::array<uint32_t, 5> h = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
            const uint64_t bit_length = size * 8;

            std::vector<uint8_t> padded_data(data, data + size);
            padded_data.push_back(0x80);

            while ((padded_data.size() % 64) != 56) {
                padded_data.push_back(0x00);
            }

            for (int i = 7; i >= 0; --i) {
                padded_data.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
            }

            for (size_t chunk = 0; chunk < padded_data.size(); chunk += 64) {
                std::array<uint32_t, 80> w = {0};
                for (size_t i = 0; i < 16; ++i) {
                    w[i] = (padded_data[chunk + i * 4] << 24) | (padded_data[chunk + i * 4 + 1] << 16) |
                           (padded_data[chunk + i * 4 + 2] << 8) | padded_data[chunk + i * 4 + 3];
                }

                for (size_t i = 16; i < 80; ++i) {
                    w[i] = rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
                }

                uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

                for (size_t i = 0; i < 80; ++i) {
                    uint32_t f, k;
                    if (i < 20) {
                        f = (b & c) | ((~b) & d);
                        k = 0x5A827999;
                    } else if (i < 40) {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1;
                    } else if (i < 60) {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDC;
                    } else {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6;
                    }

                    uint32_t temp = rotate_left(a, 5) + f + e + k + w[i];
                    e = d;
                    d = c;
                    c = rotate_left(b, 30);
                    b = a;
                    a = temp;
                }

                h[0] += a;
                h[1] += b;
                h[2] += c;
                h[3] += d;
                h[4] += e;
            }

            std::vector<uint8_t> hash;
            for (uint32_t val : h) {
                hash.push_back((val >> 24) & 0xFF);
                hash.push_back((val >> 16) & 0xFF);
                hash.push_back((val >> 8) & 0xFF);
                hash.push_back(val & 0xFF);
            }

            return hash;
        }

#if __has_include(<immintrin.h>)
        static std::vector<uint8_t> sha1_avx2(const uint8_t *data, size_t size) {
            std::array<uint32_t, 5> h = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
            const uint64_t bit_length = size * 8;

            std::vector<uint8_t> padded_data(data, data + size);
            padded_data.push_back(0x80);

            while ((padded_data.size() % 64) != 56) {
                padded_data.push_back(0x00);
            }

            for (int i = 7; i >= 0; --i) {
                padded_data.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
            }

            size_t chunk_count = padded_data.size() / 64;
            for (size_t chunk = 0; chunk < chunk_count; ++chunk) {
                // Load the 64-byte chunk into two AVX2 registers (32 bytes each)
                __m256i data_low_avx = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&padded_data[chunk * 64]));
                __m256i data_high_avx =
                    _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&padded_data[chunk * 64 + 32]));

                // Convert bytes to 32-bit words (big endian)
                alignas(32) uint32_t w_temp[16];
                // Use AVX2 to unpack bytes into 32-bit words
                __m256i shuffled_low = _mm256_shuffle_epi8(
                    data_low_avx, _mm256_set_epi8(28, 29, 30, 31, 24, 25, 26, 27, 20, 21, 22, 23, 16, 17, 18, 19, 12,
                                                  13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3));
                __m256i shuffled_high = _mm256_shuffle_epi8(
                    data_high_avx, _mm256_set_epi8(28, 29, 30, 31, 24, 25, 26, 27, 20, 21, 22, 23, 16, 17, 18, 19, 12,
                                                   13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3));

                _mm256_store_si256(reinterpret_cast<__m256i *>(w_temp), shuffled_low);
                _mm256_store_si256(reinterpret_cast<__m256i *>(&w_temp[8]), shuffled_high);

                // Initialize W[0..15]
                std::array<uint32_t, 80> w = {0};
                for (size_t i = 0; i < 16; ++i) {
                    w[i] = w_temp[i];
                }

                // Expand W[16..79] using AVX2 intrinsics
                for (size_t i = 16; i < 80; i += 8) {
                    size_t remaining = (i + 8 > 80) ? 80 - i : 8;

                    // Load previous words
                    __m256i w_m3 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&w[i - 3]));
                    __m256i w_m8 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&w[i - 8]));
                    __m256i w_m14 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&w[i - 14]));
                    __m256i w_m16 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&w[i - 16]));

                    // XOR the previous words
                    __m256i temp = _mm256_xor_si256(w_m3, w_m8);
                    temp = _mm256_xor_si256(temp, w_m14);
                    temp = _mm256_xor_si256(temp, w_m16);

                    // Rotate left by 1
                    __m256i rotated = _mm256_or_si256(_mm256_slli_epi32(temp, 1), _mm256_srli_epi32(temp, 31));

                    // Store the rotated words back to W
                    alignas(32) uint32_t rotated_temp[8];
                    _mm256_store_si256(reinterpret_cast<__m256i *>(rotated_temp), rotated);

                    for (size_t j = 0; j < remaining; ++j) {
                        w[i + j] = rotated_temp[j];
                    }
                }

                // Initialize working variables
                uint32_t a = h[0];
                uint32_t b = h[1];
                uint32_t c = h[2];
                uint32_t d = h[3];
                uint32_t e = h[4];

                // Process the 80 rounds with loop unrolling
                for (size_t i = 0; i < 80; i += 5) {
                    // Round 1: 0-19
                    if (i < 20) {
                        for (size_t j = 0; j < 5 && (i + j) < 20; ++j) {
                            uint32_t f = (b & c) | ((~b) & d);
                            uint32_t k = 0x5A827999;
                            uint32_t temp = rotate_left(a, 5) + f + e + k + w[i + j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp;
                        }
                    }
                    // Round 2: 20-39
                    else if (i < 40) {
                        for (size_t j = 0; j < 5 && (i + j) < 40; ++j) {
                            uint32_t f = b ^ c ^ d;
                            uint32_t k = 0x6ED9EBA1;
                            uint32_t temp = rotate_left(a, 5) + f + e + k + w[i + j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp;
                        }
                    }
                    // Round 3: 40-59
                    else if (i < 60) {
                        for (size_t j = 0; j < 5 && (i + j) < 60; ++j) {
                            uint32_t f = (b & c) | (b & d) | (c & d);
                            uint32_t k = 0x8F1BBCDC;
                            uint32_t temp = rotate_left(a, 5) + f + e + k + w[i + j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp;
                        }
                    }
                    // Round 4: 60-79
                    else {
                        for (size_t j = 0; j < 5 && (i + j) < 80; ++j) {
                            uint32_t f = b ^ c ^ d;
                            uint32_t k = 0xCA62C1D6;
                            uint32_t temp = rotate_left(a, 5) + f + e + k + w[i + j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp;
                        }
                    }
                }

                // Add this chunk's hash to the result so far
                h[0] += a;
                h[1] += b;
                h[2] += c;
                h[3] += d;
                h[4] += e;
            }

            // Produce the final hash value (big-endian)
            std::vector<uint8_t> hash;
            hash.reserve(20);
            for (uint32_t val : h) {
                hash.push_back((val >> 24) & 0xFF);
                hash.push_back((val >> 16) & 0xFF);
                hash.push_back((val >> 8) & 0xFF);
                hash.push_back(val & 0xFF);
            }

            return hash;
        }

        static std::vector<uint8_t> sha1_avx2(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
            std::vector<uint8_t> combined(size1 + size2);
            std::memcpy(combined.data(), data1, size1);
            std::memcpy(combined.data() + size1, data2, size2);
            return sha1_avx2(combined.data(), combined.size());
        }

        static std::vector<uint8_t> sha1_avx(const uint8_t *data, size_t size) {
            std::array<uint32_t, 5> h = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
            const uint64_t bit_length = size * 8;

            std::vector<uint8_t> padded_data(data, data + size);
            padded_data.push_back(0x80);

            while ((padded_data.size() % 64) != 56) {
                padded_data.push_back(0x00);
            }

            for (int i = 7; i >= 0; --i) {
                padded_data.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
            }

            size_t chunk_count = padded_data.size() / 64;
            for (size_t chunk = 0; chunk < chunk_count; ++chunk) {
                std::array<uint32_t, 80> w = {0};
                // Load first 16 words
                for (size_t i = 0; i < 16; ++i) {
                    w[i] = (padded_data[chunk * 64 + i * 4] << 24) | (padded_data[chunk * 64 + i * 4 + 1] << 16) |
                           (padded_data[chunk * 64 + i * 4 + 2] << 8) | padded_data[chunk * 64 + i * 4 + 3];
                }

                // SIMD 최적화를 활용한 메시지 스케줄 확장
                for (size_t i = 16; i < 80; i += 8) {
                    __m256i w_m3 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&w[i - 3]));
                    __m256i w_m8 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&w[i - 8]));
                    __m256i w_m14 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&w[i - 14]));
                    __m256i w_m16 = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&w[i - 16]));

                    __m256i temp = _mm256_xor_si256(w_m3, w_m8);
                    temp = _mm256_xor_si256(temp, w_m14);
                    temp = _mm256_xor_si256(temp, w_m16);

                    // Rotate left by 1
                    __m256i rotated = _mm256_or_si256(_mm256_slli_epi32(temp, 1), _mm256_srli_epi32(temp, 31));

                    // Store the results back
                    alignas(32) uint32_t rotated_temp[8];
                    _mm256_store_si256(reinterpret_cast<__m256i *>(rotated_temp), rotated);

                    for (size_t j = 0; j < 8 && (i + j) < 80; ++j) {
                        w[i + j] = rotated_temp[j];
                    }
                }

                uint32_t a = h[0];
                uint32_t b = h[1];
                uint32_t c = h[2];
                uint32_t d = h[3];
                uint32_t e = h[4];

                for (size_t i = 0; i < 80; ++i) {
                    uint32_t f, k;
                    if (i < 20) {
                        f = (b & c) | ((~b) & d);
                        k = 0x5A827999;
                    } else if (i < 40) {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1;
                    } else if (i < 60) {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDC;
                    } else {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6;
                    }

                    uint32_t temp = rotate_left(a, 5) + f + e + k + w[i];
                    e = d;
                    d = c;
                    c = rotate_left(b, 30);
                    b = a;
                    a = temp;
                }

                h[0] += a;
                h[1] += b;
                h[2] += c;
                h[3] += d;
                h[4] += e;
            }

            // Produce the final hash value (big-endian)
            std::vector<uint8_t> hash;
            hash.reserve(20);
            for (uint32_t val : h) {
                hash.push_back((val >> 24) & 0xFF);
                hash.push_back((val >> 16) & 0xFF);
                hash.push_back((val >> 8) & 0xFF);
                hash.push_back(val & 0xFF);
            }

            return hash;
        }

#endif

#if __has_include(<emmintrin.h>)
        static std::vector<uint8_t> sha1_sse2(const uint8_t *data, size_t size) {
            std::array<uint32_t, 5> h = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
            const uint64_t bit_length = size * 8;

            std::vector<uint8_t> padded_data(data, data + size);
            padded_data.push_back(0x80);

            while ((padded_data.size() % 64) != 56) {
                padded_data.push_back(0x00);
            }

            for (int i = 7; i >= 0; --i) {
                padded_data.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
            }

            size_t chunk_count = padded_data.size() / 64;
            for (size_t chunk = 0; chunk < chunk_count; ++chunk) {
                std::array<uint32_t, 80> w = {0};
                // Load first 16 words
                for (size_t i = 0; i < 16; ++i) {
                    w[i] = (padded_data[chunk * 64 + i * 4] << 24) | (padded_data[chunk * 64 + i * 4 + 1] << 16) |
                           (padded_data[chunk * 64 + i * 4 + 2] << 8) | padded_data[chunk * 64 + i * 4 + 3];
                }

                // SIMD 최적화를 활용한 메시지 스케줄 확장
                for (size_t i = 16; i < 80; i += 4) {
                    __m128i w_m3 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&w[i - 3]));
                    __m128i w_m8 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&w[i - 8]));
                    __m128i w_m14 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&w[i - 14]));
                    __m128i w_m16 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&w[i - 16]));

                    __m128i temp1 = _mm_xor_si128(w_m3, w_m8);
                    __m128i temp2 = _mm_xor_si128(temp1, w_m14);
                    __m128i temp3 = _mm_xor_si128(temp2, w_m16);

                    // Rotate left by 1
                    __m128i rotated = _mm_or_si128(_mm_slli_epi32(temp3, 1), _mm_srli_epi32(temp3, 31));

                    // Store the results back
                    alignas(16) uint32_t rotated_temp[4];
                    _mm_store_si128(reinterpret_cast<__m128i *>(rotated_temp), rotated);

                    for (size_t j = 0; j < 4 && (i + j) < 80; ++j) {
                        w[i + j] = rotated_temp[j];
                    }
                }

                uint32_t a = h[0];
                uint32_t b = h[1];
                uint32_t c = h[2];
                uint32_t d = h[3];
                uint32_t e = h[4];

                for (size_t i = 0; i < 80; ++i) {
                    uint32_t f, k;
                    if (i < 20) {
                        f = (b & c) | ((~b) & d);
                        k = 0x5A827999;
                    } else if (i < 40) {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1;
                    } else if (i < 60) {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDC;
                    } else {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6;
                    }

                    uint32_t temp = rotate_left(a, 5) + f + e + k + w[i];
                    e = d;
                    d = c;
                    c = rotate_left(b, 30);
                    b = a;
                    a = temp;
                }

                h[0] += a;
                h[1] += b;
                h[2] += c;
                h[3] += d;
                h[4] += e;
            }

            // Produce the final hash value (big-endian)
            std::vector<uint8_t> hash;
            hash.reserve(20);
            for (uint32_t val : h) {
                hash.push_back((val >> 24) & 0xFF);
                hash.push_back((val >> 16) & 0xFF);
                hash.push_back((val >> 8) & 0xFF);
                hash.push_back(val & 0xFF);
            }

            return hash;
        }
#endif

#if __has_include(<nmmintrin.h>)
        static std::vector<uint8_t> sha1_sse42(const uint8_t *data, size_t size) {
            std::array<uint32_t, 5> h = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
            const uint64_t bit_length = size * 8;

            std::vector<uint8_t> padded_data(data, data + size);
            padded_data.push_back(0x80);

            while ((padded_data.size() % 64) != 56) {
                padded_data.push_back(0x00);
            }

            for (int i = 7; i >= 0; --i) {
                padded_data.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
            }

            size_t chunk_count = padded_data.size() / 64;
            for (size_t chunk = 0; chunk < chunk_count; ++chunk) {
                // Load the 64-byte chunk into two SSE4.2 registers (16 bytes each)
                __m128i data_low_sse = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&padded_data[chunk * 64]));
                __m128i data_high_sse =
                    _mm_loadu_si128(reinterpret_cast<const __m128i *>(&padded_data[chunk * 64 + 16]));

                // Convert bytes to 32-bit words (big endian) using SSE4.2 intrinsics
                alignas(16) uint32_t w_temp[8];
                // Shuffle bytes to form big-endian words
                const __m128i shuffle_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

                __m128i shuffled_low = _mm_shuffle_epi8(data_low_sse, shuffle_mask);
                __m128i shuffled_high = _mm_shuffle_epi8(data_high_sse, shuffle_mask);

                _mm_store_si128(reinterpret_cast<__m128i *>(w_temp), shuffled_low);
                _mm_store_si128(reinterpret_cast<__m128i *>(&w_temp[4]), shuffled_high);

                // Initialize W[0..15]
                std::array<uint32_t, 80> w = {0};
                for (size_t i = 0; i < 8; ++i) {
                    w[i] = w_temp[i];
                }
                for (size_t i = 8; i < 16; ++i) {
                    w[i] = w_temp[i - 8];
                }

                // Expand W[16..79] using SSE4.2 intrinsics
                for (size_t i = 16; i < 80; i += 4) {
                    size_t remaining = (i + 4 > 80) ? 80 - i : 4;

                    // Load previous words
                    __m128i w_m3 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&w[i - 3]));
                    __m128i w_m8 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&w[i - 8]));
                    __m128i w_m14 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&w[i - 14]));
                    __m128i w_m16 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&w[i - 16]));

                    // XOR the previous words
                    __m128i temp = _mm_xor_si128(w_m3, w_m8);
                    temp = _mm_xor_si128(temp, w_m14);
                    temp = _mm_xor_si128(temp, w_m16);

                    // Rotate left by 1
                    __m128i rotated = _mm_or_si128(_mm_slli_epi32(temp, 1), _mm_srli_epi32(temp, 31));

                    // Store the rotated words back to W
                    alignas(16) uint32_t rotated_temp[4];
                    _mm_store_si128(reinterpret_cast<__m128i *>(rotated_temp), rotated);

                    for (size_t j = 0; j < remaining; ++j) {
                        w[i + j] = rotated_temp[j];
                    }
                }

                // Initialize working variables
                uint32_t a = h[0];
                uint32_t b = h[1];
                uint32_t c = h[2];
                uint32_t d = h[3];
                uint32_t e = h[4];

                // Process the 80 rounds with loop unrolling
                for (size_t i = 0; i < 80; i += 4) {
                    // Round 1: 0-19
                    if (i < 20) {
                        size_t end = (i + 4 < 20) ? i + 4 : 20;
                        for (size_t j = i; j < end; ++j) {
                            uint32_t f = (b & c) | ((~b) & d);
                            uint32_t k = 0x5A827999;
                            uint32_t temp_val = rotate_left(a, 5) + f + e + k + w[j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp_val;
                        }
                    }
                    // Round 2: 20-39
                    else if (i < 40) {
                        size_t end = (i + 4 < 40) ? i + 4 : 40;
                        for (size_t j = i; j < end; ++j) {
                            uint32_t f = b ^ c ^ d;
                            uint32_t k = 0x6ED9EBA1;
                            uint32_t temp_val = rotate_left(a, 5) + f + e + k + w[j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp_val;
                        }
                    }
                    // Round 3: 40-59
                    else if (i < 60) {
                        size_t end = (i + 4 < 60) ? i + 4 : 60;
                        for (size_t j = i; j < end; ++j) {
                            uint32_t f = (b & c) | (b & d) | (c & d);
                            uint32_t k = 0x8F1BBCDC;
                            uint32_t temp_val = rotate_left(a, 5) + f + e + k + w[j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp_val;
                        }
                    }
                    // Round 4: 60-79
                    else {
                        size_t end = (i + 4 < 80) ? i + 4 : 80;
                        for (size_t j = i; j < end; ++j) {
                            uint32_t f = b ^ c ^ d;
                            uint32_t k = 0xCA62C1D6;
                            uint32_t temp_val = rotate_left(a, 5) + f + e + k + w[j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp_val;
                        }
                    }
                }

                // Add this chunk's hash to the result so far
                h[0] += a;
                h[1] += b;
                h[2] += c;
                h[3] += d;
                h[4] += e;
            }

            // Produce the final hash value (big-endian)
            std::vector<uint8_t> hash;
            hash.reserve(20);
            for (uint32_t val : h) {
                hash.push_back((val >> 24) & 0xFF);
                hash.push_back((val >> 16) & 0xFF);
                hash.push_back((val >> 8) & 0xFF);
                hash.push_back(val & 0xFF);
            }

            return hash;
        }
#endif

#if defined(__ANDROID__) || (defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR))
        static std::vector<uint8_t> sha1_neon(const uint8_t *data, size_t size) {
            std::array<uint32_t, 5> h = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
            const uint64_t bit_length = size * 8;

            std::vector<uint8_t> padded_data(data, data + size);
            padded_data.push_back(0x80);

            while ((padded_data.size() % 64) != 56) {
                padded_data.push_back(0x00);
            }

            for (int i = 7; i >= 0; --i) {
                padded_data.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
            }

            size_t chunk_count = padded_data.size() / 64;
            for (size_t chunk = 0; chunk < chunk_count; ++chunk) {
                // Load the 64-byte chunk into NEON registers
                uint8x16_t data_low_neon = vld1q_u8(&padded_data[chunk * 64]);
                uint8x16_t data_high_neon = vld1q_u8(&padded_data[chunk * 64 + 16]);

                // Convert bytes to 32-bit words (big endian) using NEON intrinsics
                alignas(16) uint32_t w_temp[8];
                // Swap byte order for big endian
                uint32x4_t w0 = vreinterpretq_u32_u8(vrev32q_u8(data_low_neon));
                uint32x4_t w1 = vreinterpretq_u32_u8(vrev32q_u8(data_high_neon));

                vst1q_u32(&w_temp[0], w0);
                vst1q_u32(&w_temp[4], w1);

                // Initialize W[0..15]
                std::array<uint32_t, 80> w = {0};
                for (size_t i = 0; i < 8; ++i) {
                    w[i] = w_temp[i];
                }
                for (size_t i = 8; i < 16; ++i) {
                    w[i] = w_temp[i - 8];
                }

                // Expand W[16..79] using NEON intrinsics
                for (size_t i = 16; i < 80; i += 4) {
                    size_t remaining = (i + 4 > 80) ? 80 - i : 4;

                    // Load previous words
                    uint32x4_t w_m3 = vld1q_u32(&w[i - 3]);
                    uint32x4_t w_m8 = vld1q_u32(&w[i - 8]);
                    uint32x4_t w_m14 = vld1q_u32(&w[i - 14]);
                    uint32x4_t w_m16 = vld1q_u32(&w[i - 16]);

                    // XOR the previous words
                    uint32x4_t temp = veorq_u32(w_m3, w_m8);
                    temp = veorq_u32(temp, w_m14);
                    temp = veorq_u32(temp, w_m16);

                    // Rotate left by 1
                    uint32x4_t rotated = vorrq_u32(vshlq_n_u32(temp, 1), vshrq_n_u32(temp, 31));

                    // Store the rotated words back to W
                    alignas(16) uint32_t rotated_temp[4];
                    vst1q_u32(rotated_temp, rotated);

                    for (size_t j = 0; j < remaining; ++j) {
                        w[i + j] = rotated_temp[j];
                    }
                }

                // Initialize working variables
                uint32_t a = h[0];
                uint32_t b = h[1];
                uint32_t c = h[2];
                uint32_t d = h[3];
                uint32_t e = h[4];

                // Process the 80 rounds with loop unrolling
                for (size_t i = 0; i < 80; i += 4) {
                    // Round 1: 0-19
                    if (i < 20) {
                        size_t end = (i + 4 < 20) ? i + 4 : 20;
                        for (size_t j = i; j < end; ++j) {
                            uint32_t f = (b & c) | ((~b) & d);
                            uint32_t k = 0x5A827999;
                            uint32_t temp_val = rotate_left(a, 5) + f + e + k + w[j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp_val;
                        }
                    }
                    // Round 2: 20-39
                    else if (i < 40) {
                        size_t end = (i + 4 < 40) ? i + 4 : 40;
                        for (size_t j = i; j < end; ++j) {
                            uint32_t f = b ^ c ^ d;
                            uint32_t k = 0x6ED9EBA1;
                            uint32_t temp_val = rotate_left(a, 5) + f + e + k + w[j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp_val;
                        }
                    }
                    // Round 3: 40-59
                    else if (i < 60) {
                        size_t end = (i + 4 < 60) ? i + 4 : 60;
                        for (size_t j = i; j < end; ++j) {
                            uint32_t f = (b & c) | (b & d) | (c & d);
                            uint32_t k = 0x8F1BBCDC;
                            uint32_t temp_val = rotate_left(a, 5) + f + e + k + w[j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp_val;
                        }
                    }
                    // Round 4: 60-79
                    else {
                        size_t end = (i + 4 < 80) ? i + 4 : 80;
                        for (size_t j = i; j < end; ++j) {
                            uint32_t f = b ^ c ^ d;
                            uint32_t k = 0xCA62C1D6;
                            uint32_t temp_val = rotate_left(a, 5) + f + e + k + w[j];
                            e = d;
                            d = c;
                            c = rotate_left(b, 30);
                            b = a;
                            a = temp_val;
                        }
                    }
                }

                // Add this chunk's hash to the result so far
                h[0] += a;
                h[1] += b;
                h[2] += c;
                h[3] += d;
                h[4] += e;
            }

            // Produce the final hash value (big-endian)
            std::vector<uint8_t> hash;
            hash.reserve(20);
            for (uint32_t val : h) {
                hash.push_back((val >> 24) & 0xFF);
                hash.push_back((val >> 16) & 0xFF);
                hash.push_back((val >> 8) & 0xFF);
                hash.push_back(val & 0xFF);
            }

            return hash;
        }
#endif
       private:
        static uint32_t rotate_left(uint32_t value, size_t bits) { return (value << bits) | (value >> (32 - bits)); }
    };
#endif  // !__has_include(<openssl/hmac.h>)
};

#endif  // HMAC_SHA1_HPP
