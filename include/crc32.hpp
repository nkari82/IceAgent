#ifndef CRC32_HPP
#define CRC32_HPP

#include <array>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

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

class CRC32 {
   public:
    static uint32_t calculate(const std::vector<uint8_t>& data) {
        static auto crc_func = select_crc_function();
        return crc_func(data);
    }

   private:
    using CRCFunction = uint32_t (*)(const std::vector<uint8_t>&);

    enum class FeatureIndex : int { NONE = -1, ARM_CRC32, NEON, AVX2, AVX, SSE42, SSE2 };

    static CRCFunction select_crc_function() {
        switch (detect_supported_feature()) {
#if defined(__ANDROID__) || (defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR))
#if defined(__ARM_FEATURE_CRC32)
            case FeatureIndex::ARM_CRC32:
                return calculate_arm_crc32;
#endif
            case FeatureIndex::NEON:
                return calculate_neon;
#endif
#if __has_include(<immintrin.h>)
            case FeatureIndex::AVX2:
                return calculate_avx2;
            case FeatureIndex::AVX:
                return calculate_avx;
#endif
#if __has_include(<nmmintrin.h>)
            case FeatureIndex::SSE42:
                return calculate_sse42;
#endif
#if __has_include(<emmintrin.h>)
            case FeatureIndex::SSE2:
                return calculate_sse2;
#endif
            default:
                return calculate_generic;
        }
    }

    static FeatureIndex detect_supported_feature() {
#if defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR)
        // Apple 플랫폼에서는 ARM CRC32 지원 여부를 추가적으로 확인할 필요가 있습니다.
        // 여기서는 단순히 NEON을 지원한다고 가정합니다.
        return FeatureIndex::NEON;
#elif defined(__ANDROID__)
        std::ifstream cpuinfo("/proc/cpuinfo");
        if (cpuinfo.is_open()) {
            std::string line;
            while (std::getline(cpuinfo, line)) {
                if (line.find("crc32") != std::string::npos)
                    return FeatureIndex::ARM_CRC32;
            }
        }
        return FeatureIndex::NEON;
#elif defined(_WIN32) || defined(__linux__)  // x86
        unsigned int reg[4]{0};
#if __has_include(<intrin.h>)
        __cpuid((int*)reg, 1);
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
        __cpuid((int*)reg, 7);
#elif defined(__GNUC__) || defined(__clang__)
        __get_cpuid(7, &reg[0], &reg[1], &reg[2], &reg[3]);
#endif
        if ((reg[1] & (1 << 5)) != 0)
            return FeatureIndex::AVX2;
#endif
        return FeatureIndex::NONE;
    }

    static uint32_t calculate_generic(const std::vector<uint8_t>& data) {
        static const std::array<uint32_t, 256> crc_table = [] {
            std::array<uint32_t, 256> table = {};
            for (uint32_t i = 0; i < 256; ++i) {
                uint32_t crc = i;
                for (uint32_t j = 0; j < 8; ++j) {
                    crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
                }
                table[i] = crc;
            }
            return table;
        }();

        uint32_t crc = 0xFFFFFFFF;
        for (uint8_t byte : data) {
            crc = (crc >> 8) ^ crc_table[(crc ^ byte) & 0xFF];
        }
        return ~crc;
    }

#if defined(__ANDROID__) || (defined(__APPLE__) && (TARGET_OS_IPHONE || TARGET_OS_SIMULATOR))
#if defined(__ARM_FEATURE_CRC32)
    static uint32_t calculate_arm_crc32(const std::vector<uint8_t>& data) {
        uint32_t crc = 0xFFFFFFFF;
        for (size_t i = 0; i < data.size(); ++i) {
            crc = __crc32b(crc, data[i]);
        }
        return ~crc;
    }
#endif

    static uint32_t calculate_neon(const std::vector<uint8_t>& data) {
        uint32_t crc = 0xFFFFFFFF;
        size_t i = 0;
        size_t size = data.size();

        // Process 16 bytes at a time
        for (; i + 16 <= size; i += 16) {
            uint8x16_t chunk = vld1q_u8(&data[i]);
            uint8_t bytes[16];
            vst1q_u8(bytes, chunk);
            for (int j = 0; j < 16; ++j) {
                crc = (crc >> 8) ^ ((crc ^ bytes[j]) & 0xFF);
            }
        }

        // Process remaining bytes
        for (; i < size; ++i) {
            crc = (crc >> 8) ^ ((crc ^ data[i]) & 0xFF);
        }

        return ~crc;
    }
#endif

#if __has_include(<immintrin.h>)
    static uint32_t calculate_avx2(const std::vector<uint8_t>& data) {
        uint32_t crc = 0xFFFFFFFF;
        size_t i = 0;
        size_t size = data.size();

        for (; i + 32 <= size; i += 32) {
            __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&data[i]));
            uint8_t bytes[32];
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(bytes), chunk);
            for (int j = 0; j < 32; ++j) {
                crc = _mm_crc32_u8(crc, bytes[j]);
            }
        }
        for (; i < size; ++i) {
            crc = _mm_crc32_u8(crc, data[i]);
        }
        return ~crc;
    }

    static uint32_t calculate_avx(const std::vector<uint8_t>& data) {
        uint32_t crc = 0xFFFFFFFF;
        size_t i = 0;
        size_t size = data.size();

        for (; i + 32 <= size; i += 32) {  // AVX can handle 32 bytes
            __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(&data[i]));
            uint8_t bytes[32];
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(bytes), chunk);
            for (int j = 0; j < 32; ++j) {
                crc = _mm_crc32_u8(crc, bytes[j]);
            }
        }
        for (; i < size; ++i) {
            crc = _mm_crc32_u8(crc, data[i]);
        }
        return ~crc;
    }
#endif

#if __has_include(<nmmintrin.h>)
    static uint32_t calculate_sse42(const std::vector<uint8_t>& data) {
        uint32_t crc = 0xFFFFFFFF;
        for (uint8_t byte : data) {
            crc = _mm_crc32_u8(crc, byte);
        }
        return ~crc;
    }
#endif

#if __has_include(<emmintrin.h>)
    static uint32_t calculate_sse2(const std::vector<uint8_t>& data) {
        uint32_t crc = 0xFFFFFFFF;
        size_t i = 0;
        size_t size = data.size();

        __m128i crc_vec = _mm_set1_epi32(0xFFFFFFFF);
        const __m128i poly = _mm_set1_epi32(0xEDB88320);

        for (; i + 16 <= size; i += 16) {
            __m128i chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&data[i]));
            uint8_t bytes[16];
            _mm_storeu_si128(reinterpret_cast<__m128i*>(bytes), chunk);
            for (int j = 0; j < 16; ++j) {
                uint8_t byte = bytes[j];
                __m128i crc_byte = _mm_set1_epi32(byte);
                crc_vec = _mm_xor_si128(crc_vec, crc_byte);
                for (int k = 0; k < 8; ++k) {
                    __m128i mask = _mm_and_si128(crc_vec, _mm_set1_epi32(1));
                    crc_vec = _mm_srli_epi32(crc_vec, 1);
                    crc_vec = _mm_xor_si128(crc_vec, _mm_and_si128(mask, poly));
                }
            }
        }

        // Extract CRC from SIMD register
        crc = _mm_cvtsi128_si32(crc_vec);

        // Process remaining bytes
        for (; i < size; ++i) {
            crc = (crc >> 8) ^ ((crc ^ data[i]) & 0xFF);
        }

        return ~crc;
    }
#endif
};

#endif  // CRC32_HPP
