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
            case FeatureIndex::AVX2:
                return hmac_avx2;
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

    // 기본 HMAC-SHA1 구현 (비최적화)
    static std::vector<uint8_t> hmac_generic(const std::string &key, const std::vector<uint8_t> &data) {
        const size_t block_size = 64;  // SHA-1 block size
        const size_t hash_size = 20;   // SHA-1 output size

        std::vector<uint8_t> key_pad(block_size, 0);
        if (key.size() > block_size) {
            // 키가 블록 사이즈보다 큰 경우 SHA1 해싱
            std::vector<uint8_t> hashed_key =
                SHA1::sha1_generic(reinterpret_cast<const uint8_t *>(key.data()), key.size());
            std::copy(hashed_key.begin(), hashed_key.end(), key_pad.begin());
        } else {
            // 키를 패딩
            std::copy(key.begin(), key.end(), key_pad.begin());
        }

        std::vector<uint8_t> o_key_pad(block_size, 0x5c);
        std::vector<uint8_t> i_key_pad(block_size, 0x36);
        for (size_t i = 0; i < block_size; ++i) {
            o_key_pad[i] ^= key_pad[i];
            i_key_pad[i] ^= key_pad[i];
        }

        // 내부 해시 계산
        std::vector<uint8_t> inner_hash = SHA1::sha1(i_key_pad.data(), i_key_pad.size(), data.data(), data.size());
        // 외부 해시 계산
        std::vector<uint8_t> result =
            SHA1::sha1(o_key_pad.data(), o_key_pad.size(), inner_hash.data(), inner_hash.size());

        return result;
    }

// AVX2 최적화된 HMAC-SHA1 구현
#if __has_include(<immintrin.h>)
    static std::vector<uint8_t> hmac_avx2(const std::string &key, const std::vector<uint8_t> &data) {
        // AVX2를 활용한 최적화된 HMAC-SHA1 구현
        // 실제 구현에서는 AVX2 명령어를 활용하여 병렬 처리 등을 수행해야 합니다.
        // 여기서는 예시로 기본 구현을 호출합니다.
        return hmac_generic(key, data);
    }
#endif

// SSE4.2 최적화된 HMAC-SHA1 구현
#if __has_include(<nmmintrin.h>)
    static std::vector<uint8_t> hmac_sse42(const std::string &key, const std::vector<uint8_t> &data) {
        // SSE4.2를 활용한 최적화된 HMAC-SHA1 구현
        // 실제 구현에서는 SSE4.2 명령어를 활용하여 병렬 처리 등을 수행해야 합니다.
        // 여기서는 예시로 기본 구현을 호출합니다.
        return hmac_generic(key, data);
    }
#endif

// NEON 최적화된 HMAC-SHA1 구현
#if defined(__ANDROID__) || (defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR))
    static std::vector<uint8_t> hmac_neon(const std::string &key, const std::vector<uint8_t> &data) {
        // NEON을 활용한 최적화된 HMAC-SHA1 구현
        // 실제 구현에서는 NEON 명령어를 활용하여 병렬 처리 등을 수행해야 합니다.
        // 여기서는 예시로 기본 구현을 호출합니다.
        return hmac_generic(key, data);
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
            // AVX2를 활용한 최적화된 SHA1 구현 예제
            // 실제 구현에서는 256비트 레지스터를 활용하여 데이터 블록을 병렬로 처리합니다.
            // 여기서는 기본 구현을 호출하지만, 실제로는 AVX2 명령어를 활용하여 병렬 처리를 구현해야 합니다.

            // 예시: 데이터 블록을 32바이트씩 처리
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
                __m256i w_avx = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(&padded_data[chunk * 64]));

                // 실제로는 AVX2를 활용하여 w 배열을 벡터화하여 처리
                // 여기서는 간단히 기본 구현을 호출
                std::array<uint32_t, 80> w = {0};
                for (size_t i = 0; i < 16; ++i) {
                    w[i] = (padded_data[chunk * 64 + i * 4] << 24) | (padded_data[chunk * 64 + i * 4 + 1] << 16) |
                           (padded_data[chunk * 64 + i * 4 + 2] << 8) | padded_data[chunk * 64 + i * 4 + 3];
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

        static std::vector<uint8_t> sha1_avx2(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
            std::vector<uint8_t> combined(size1 + size2);
            std::memcpy(combined.data(), data1, size1);
            std::memcpy(combined.data() + size1, data2, size2);
            return sha1_avx2(combined.data(), combined.size());
        }
#endif

#if __has_include(<nmmintrin.h>)
        static std::vector<uint8_t> sha1_sse42(const uint8_t *data, size_t size) {
            // SSE4.2를 활용한 최적화된 SHA1 구현 예제
            // 실제 구현에서는 SSE4.2 명령어를 활용하여 데이터 블록을 병렬로 처리합니다.
            // 여기서는 기본 구현을 호출하지만, 실제로는 SSE4.2 명령어를 활용하여 병렬 처리를 구현해야 합니다.

            // 예시: 데이터 블록을 16바이트씩 처리
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
                __m128i w_sse = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&padded_data[chunk * 64]));

                // 실제로는 SSE4.2를 활용하여 w 배열을 벡터화하여 처리
                // 여기서는 간단히 기본 구현을 호출
                std::array<uint32_t, 80> w = {0};
                for (size_t i = 0; i < 16; ++i) {
                    w[i] = (padded_data[chunk * 64 + i * 4] << 24) | (padded_data[chunk * 64 + i * 4 + 1] << 16) |
                           (padded_data[chunk * 64 + i * 4 + 2] << 8) | padded_data[chunk * 64 + i * 4 + 3];
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

        static std::vector<uint8_t> sha1_sse42(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
            std::vector<uint8_t> combined(size1 + size2);
            std::memcpy(combined.data(), data1, size1);
            std::memcpy(combined.data() + size1, data2, size2);
            return sha1_sse42(combined.data(), combined.size());
        }
#endif

#if defined(__ANDROID__) || (defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR))
        static std::vector<uint8_t> sha1_neon(const uint8_t *data, size_t size) {
            // NEON을 활용한 최적화된 SHA1 구현 예제
            // 실제 구현에서는 NEON 명령어를 활용하여 데이터 블록을 병렬로 처리합니다.
            // 여기서는 기본 구현을 호출하지만, 실제로는 NEON 명령어를 활용하여 병렬 처리를 구현해야 합니다.

            // 예시: 데이터 블록을 16바이트씩 처리
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
                uint8x16_t w_neon = vld1q_u8(&padded_data[chunk * 64]);

                // 실제로는 NEON을 활용하여 w 배열을 벡터화하여 처리
                // 여기서는 간단히 기본 구현을 호출
                std::array<uint32_t, 80> w = {0};
                for (size_t i = 0; i < 16; ++i) {
                    w[i] = (padded_data[chunk * 64 + i * 4] << 24) | (padded_data[chunk * 64 + i * 4 + 1] << 16) |
                           (padded_data[chunk * 64 + i * 4 + 2] << 8) | padded_data[chunk * 64 + i * 4 + 3];
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

        static std::vector<uint8_t> sha1_neon(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
            std::vector<uint8_t> combined(size1 + size2);
            std::memcpy(combined.data(), data1, size1);
            std::memcpy(combined.data() + size1, data2, size2);
            return sha1_neon(combined.data(), combined.size());
        }

#endif
        // SHA1 함수 오버로드: 두 개의 데이터 블록을 결합하여 SHA1 해싱
        static std::vector<uint8_t> sha1(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2) {
            std::vector<uint8_t> combined(size1 + size2);
            std::memcpy(combined.data(), data1, size1);
            std::memcpy(combined.data() + size1, data2, size2);
            return sha1_generic(combined.data(), combined.size());
        }

       private:
        static uint32_t rotate_left(uint32_t value, size_t bits) { return (value << bits) | (value >> (32 - bits)); }
    };

    // 커스텀 HMAC-SHA1 구현
    static std::vector<uint8_t> hmac_generic(const std::string &key, const std::vector<uint8_t> &data) {
        const size_t block_size = 64;  // SHA-1 block size
        const size_t hash_size = 20;   // SHA-1 output size

        std::vector<uint8_t> key_pad(block_size, 0);
        if (key.size() > block_size) {
            // 키가 블록 사이즈보다 큰 경우 SHA1 해싱
            std::vector<uint8_t> hashed_key =
                SHA1::sha1_generic(reinterpret_cast<const uint8_t *>(key.data()), key.size());
            std::copy(hashed_key.begin(), hashed_key.end(), key_pad.begin());
        } else {
            // 키를 패딩
            std::copy(key.begin(), key.end(), key_pad.begin());
        }

        std::vector<uint8_t> o_key_pad(block_size, 0x5c);
        std::vector<uint8_t> i_key_pad(block_size, 0x36);
        for (size_t i = 0; i < block_size; ++i) {
            o_key_pad[i] ^= key_pad[i];
            i_key_pad[i] ^= key_pad[i];
        }

        // 내부 해시 계산
        std::vector<uint8_t> inner_hash = SHA1::sha1(i_key_pad.data(), i_key_pad.size(), data.data(), data.size());
        // 외부 해시 계산
        std::vector<uint8_t> result =
            SHA1::sha1(o_key_pad.data(), o_key_pad.size(), inner_hash.data(), inner_hash.size());

        return result;
    }

#if __has_include(<immintrin.h>)
    static std::vector<uint8_t> hmac_avx2(const std::string &key, const std::vector<uint8_t> &data) {
        const size_t block_size = 64;  // SHA-1 block size
        const size_t hash_size = 20;   // SHA-1 output size

        std::vector<uint8_t> key_pad(block_size, 0);
        if (key.size() > block_size) {
            // 키가 블록 사이즈보다 큰 경우 SHA1 해싱
            std::vector<uint8_t> hashed_key =
                SHA1::sha1_avx2(reinterpret_cast<const uint8_t *>(key.data()), key.size());
            std::copy(hashed_key.begin(), hashed_key.end(), key_pad.begin());
        } else {
            // 키를 패딩
            std::copy(key.begin(), key.end(), key_pad.begin());
        }

        std::vector<uint8_t> o_key_pad(block_size, 0x5c);
        std::vector<uint8_t> i_key_pad(block_size, 0x36);
        for (size_t i = 0; i < block_size; ++i) {
            o_key_pad[i] ^= key_pad[i];
            i_key_pad[i] ^= key_pad[i];
        }

        // 내부 해시 계산
        std::vector<uint8_t> inner_hash = SHA1::sha1_avx2(i_key_pad.data(), i_key_pad.size(), data.data(), data.size());
        // 외부 해시 계산
        std::vector<uint8_t> result =
            SHA1::sha1_avx2(o_key_pad.data(), o_key_pad.size(), inner_hash.data(), inner_hash.size());

        return result;
    }
#endif

// SSE4.2 최적화된 HMAC-SHA1 구현
#if __has_include(<nmmintrin.h>)
    static std::vector<uint8_t> hmac_sse42(const std::string &key, const std::vector<uint8_t> &data) {
        const size_t block_size = 64;  // SHA-1 block size
        const size_t hash_size = 20;   // SHA-1 output size

        std::vector<uint8_t> key_pad(block_size, 0);
        if (key.size() > block_size) {
            // 키가 블록 사이즈보다 큰 경우 SHA1 해싱
            std::vector<uint8_t> hashed_key =
                SHA1::sha1_sse42(reinterpret_cast<const uint8_t *>(key.data()), key.size());
            std::copy(hashed_key.begin(), hashed_key.end(), key_pad.begin());
        } else {
            // 키를 패딩
            std::copy(key.begin(), key.end(), key_pad.begin());
        }

        std::vector<uint8_t> o_key_pad(block_size, 0x5c);
        std::vector<uint8_t> i_key_pad(block_size, 0x36);
        for (size_t i = 0; i < block_size; ++i) {
            o_key_pad[i] ^= key_pad[i];
            i_key_pad[i] ^= key_pad[i];
        }

        // 내부 해시 계산
        std::vector<uint8_t> inner_hash =
            SHA1::sha1_sse42(i_key_pad.data(), i_key_pad.size(), data.data(), data.size());
        // 외부 해시 계산
        std::vector<uint8_t> result =
            SHA1::sha1_sse42(o_key_pad.data(), o_key_pad.size(), inner_hash.data(), inner_hash.size());

        return result;
    }
#endif

// NEON 최적화된 HMAC-SHA1 구현
#if defined(__ANDROID__) || (defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR))
    static std::vector<uint8_t> hmac_neon(const std::string &key, const std::vector<uint8_t> &data) {
        const size_t block_size = 64;  // SHA-1 block size
        const size_t hash_size = 20;   // SHA-1 output size

        std::vector<uint8_t> key_pad(block_size, 0);
        if (key.size() > block_size) {
            // 키가 블록 사이즈보다 큰 경우 SHA1 해싱
            std::vector<uint8_t> hashed_key =
                SHA1::sha1_neon(reinterpret_cast<const uint8_t *>(key.data()), key.size());
            std::copy(hashed_key.begin(), hashed_key.end(), key_pad.begin());
        } else {
            // 키를 패딩
            std::copy(key.begin(), key.end(), key_pad.begin());
        }

        std::vector<uint8_t> o_key_pad(block_size, 0x5c);
        std::vector<uint8_t> i_key_pad(block_size, 0x36);
        for (size_t i = 0; i < block_size; ++i) {
            o_key_pad[i] ^= key_pad[i];
            i_key_pad[i] ^= key_pad[i];
        }

        // 내부 해시 계산
        std::vector<uint8_t> inner_hash = SHA1::sha1_neon(i_key_pad.data(), i_key_pad.size(), data.data(), data.size());
        // 외부 해시 계산
        std::vector<uint8_t> result =
            SHA1::sha1_neon(o_key_pad.data(), o_key_pad.size(), inner_hash.data(), inner_hash.size());

        return result;
    }
#endif

#endif  // !__has_include(<openssl/hmac.h>)

   private:
    // SHA1 클래스는 HMAC-SHA1 구현에 사용됩니다.
    // OpenSSL을 사용할 때는 별도의 구현이 필요 없으므로 이 클래스는 OpenSSL 미사용 시에만 사용됩니다.
};

#endif  // HMAC_SHA1_HPP
