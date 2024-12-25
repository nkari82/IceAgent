// include/hmac_sha1.hpp

#ifndef HMAC_SHA1_HPP
#define HMAC_SHA1_HPP

#include <vector>
#include <string>
#include <array>
#include <stdexcept>
#include <cstdint>

#if __has_include(<openssl/hmac.h>)
#include <openssl/hmac.h>
#include <openssl/sha.h>
#endif

class HmacSha1
{
public:
#if __has_include(<openssl/hmac.h>)
    static std::vector<uint8_t> calculate(const std::string &key, const std::vector<uint8_t> &data)
    {
        const unsigned char *key_ptr = reinterpret_cast<const unsigned char *>(key.data());
        const unsigned char *data_ptr = data.data();

        unsigned char result[EVP_MAX_MD_SIZE];
        unsigned int result_len = 0;

        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
        {
            throw std::runtime_error("Failed to create HMAC context");
        }

        if (!HMAC_Init_ex(ctx, key_ptr, static_cast<int>(key.size()), EVP_sha1(), nullptr))
        {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize HMAC context");
        }

        if (!HMAC_Update(ctx, data_ptr, data.size()))
        {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("Failed to update HMAC");
        }

        if (!HMAC_Final(ctx, result, &result_len))
        {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize HMAC");
        }

        HMAC_CTX_free(ctx);

        return std::vector<uint8_t>(result, result + result_len);
    }

#else

    static uint32_t rotate_left(uint32_t value, size_t bits)
    {
        return (value << bits) | (value >> (32 - bits));
    }

    static std::vector<uint8_t> sha1(const uint8_t *data, size_t size)
    {
        std::array<uint32_t, 5> h = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
        const uint64_t bit_length = size * 8;

        std::vector<uint8_t> padded_data(data, data + size);
        padded_data.push_back(0x80);

        while ((padded_data.size() % 64) != 56)
        {
            padded_data.push_back(0x00);
        }

        for (int i = 7; i >= 0; --i)
        {
            padded_data.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
        }

        for (size_t chunk = 0; chunk < padded_data.size(); chunk += 64)
        {
            std::array<uint32_t, 80> w = {0};
            for (size_t i = 0; i < 16; ++i)
            {
                w[i] = (padded_data[chunk + i * 4] << 24) |
                       (padded_data[chunk + i * 4 + 1] << 16) |
                       (padded_data[chunk + i * 4 + 2] << 8) |
                       padded_data[chunk + i * 4 + 3];
            }

            for (size_t i = 16; i < 80; ++i)
            {
                w[i] = rotate_left(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }

            uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

            for (size_t i = 0; i < 80; ++i)
            {
                uint32_t f, k;
                if (i < 20)
                {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                }
                else if (i < 40)
                {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if (i < 60)
                {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else
                {
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
        for (uint32_t val : h)
        {
            hash.push_back((val >> 24) & 0xFF);
            hash.push_back((val >> 16) & 0xFF);
            hash.push_back((val >> 8) & 0xFF);
            hash.push_back(val & 0xFF);
        }

        return hash;
    }

    static std::vector<uint8_t> sha1(const uint8_t *data1, size_t size1, const uint8_t *data2, size_t size2)
    {
        std::vector<uint8_t> combined(size1 + size2);
        std::memcpy(combined.data(), data1, size1);
        std::memcpy(combined.data() + size1, data2, size2);
        return sha1(combined.data(), combined.size());
    }

    static std::vector<uint8_t> calculate(const std::string &key, const std::vector<uint8_t> &data)
    {
        const size_t block_size = 64; // SHA-1 block size
        const size_t hash_size = 20;  // SHA-1 output size

        std::vector<uint8_t> key_pad(block_size, 0);
        if (key.size() > block_size)
        {
            key_pad.assign(sha1(reinterpret_cast<const uint8_t *>(key.data()), key.size()).begin(), sha1(reinterpret_cast<const uint8_t *>(key.data()), key.size()).end());
        }
        else
        {
            std::copy(key.begin(), key.end(), key_pad.begin());
        }

        std::vector<uint8_t> o_key_pad(block_size, 0x5c);
        std::vector<uint8_t> i_key_pad(block_size, 0x36);
        for (size_t i = 0; i < block_size; ++i)
        {
            o_key_pad[i] ^= key_pad[i];
            i_key_pad[i] ^= key_pad[i];
        }

        std::vector<uint8_t> inner_hash = sha1(i_key_pad.data(), i_key_pad.size(), data.data(), data.size());
        std::vector<uint8_t> result = sha1(o_key_pad.data(), o_key_pad.size(), inner_hash.data(), inner_hash.size());

        return result;
    }
};

#endif // __has_include(<openssl/hmac.h>)
#endif // HMAC_SHA1_HPP
