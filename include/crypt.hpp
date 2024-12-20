// include/crypt.hpp

#ifndef CRYPT_HPP
#define CRYPT_HPP

#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>
#include <cstring>
#include <algorithm>

// Check for OpenSSL headers
#if __has_include(<openssl/hmac.h>) && __has_include(<openssl/sha.h>)
    #include <openssl/hmac.h>
    #include <openssl/sha.h>
    #define USE_OPENSSL
#endif

namespace Crypt {

    // Pure C++ SHA1 Implementation
    class SHA1_CPP {
    public:
        SHA1_CPP() {
            reset();
        }

        void update(const uint8_t* data, size_t len) {
            size_t i = 0;

            // Fill the buffer
            if (buffer_size_ > 0) {
                size_t to_fill = 64 - buffer_size_;
                if (len < to_fill) {
                    std::copy(data, data + len, buffer_ + buffer_size_);
                    buffer_size_ += len;
                    total_size_ += len;
                    return;
                }
                else {
                    std::copy(data, data + to_fill, buffer_ + buffer_size_);
                    process_block(buffer_);
                    i += to_fill;
                    buffer_size_ = 0;
                }
            }

            // Process blocks directly from input data
            for (; i + 64 <= len; i += 64) {
                process_block(data + i);
            }

            // Copy remaining bytes to buffer
            if (i < len) {
                std::copy(data + i, data + len, buffer_ + buffer_size_);
                buffer_size_ += (len - i);
                total_size_ += (len - i);
            }
        }

        void finalize() {
            // Padding
            uint64_t total_bits = (total_size_ + buffer_size_) * 8;
            buffer_[buffer_size_] = 0x80;
            buffer_size_++;
            if (buffer_size_ > 56) {
                while (buffer_size_ < 64) buffer_[buffer_size_++] = 0x00;
                process_block(buffer_);
                buffer_size_ = 0;
            }
            while (buffer_size_ < 56) buffer_[buffer_size_++] = 0x00;

            // Append total bits
            for (int i = 7; i >= 0; --i) {
                buffer_[buffer_size_++] = (total_bits >> (i * 8)) & 0xFF;
            }

            process_block(buffer_);
        }

        std::vector<uint8_t> digest() const {
            std::vector<uint8_t> out(20);
            for (int i = 0; i < 5; ++i) {
                out[i * 4 + 0] = (h_[i] >> 24) & 0xFF;
                out[i * 4 + 1] = (h_[i] >> 16) & 0xFF;
                out[i * 4 + 2] = (h_[i] >> 8) & 0xFF;
                out[i * 4 + 3] = (h_[i] & 0xFF);
            }
            return out;
        }

    private:
        uint32_t h_[5];
        uint8_t buffer_[64];
        size_t buffer_size_;
        uint64_t total_size_;

        void reset() {
            h_[0] = 0x67452301;
            h_[1] = 0xEFCDAB89;
            h_[2] = 0x98BADCFE;
            h_[3] = 0x10325476;
            h_[4] = 0xC3D2E1F0;
            buffer_size_ = 0;
            total_size_ = 0;
        }

        void process_block(const uint8_t* block) {
            uint32_t w[80];
            for (int i = 0; i < 16; ++i) {
                w[i] = (block[i * 4 + 0] << 24) |
                       (block[i * 4 + 1] << 16) |
                       (block[i * 4 + 2] << 8) |
                       (block[i * 4 + 3]);
            }
            for (int i = 16; i < 80; ++i) {
                w[i] = left_rotate((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
            }

            uint32_t a = h_[0];
            uint32_t b = h_[1];
            uint32_t c = h_[2];
            uint32_t d = h_[3];
            uint32_t e = h_[4];

            for (int i = 0; i < 80; ++i) {
                uint32_t f, k;
                if (i < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                }
                else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                uint32_t temp = left_rotate(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = left_rotate(b, 30);
                b = a;
                a = temp;
            }

            h_[0] += a;
            h_[1] += b;
            h_[2] += c;
            h_[3] += d;
            h_[4] += e;

            total_size_ += 64;
        }

        uint32_t left_rotate(uint32_t value, int bits) const {
            return (value << bits) | (value >> (32 - bits));
        }
    };

    // Pure C++ HMAC-SHA1 Implementation
    std::vector<uint8_t> hmac_sha1_cpp(const std::string& key, const std::vector<uint8_t>& data) {
        const size_t block_size = 64; // Block size for SHA1

        std::vector<uint8_t> key_padded(block_size, 0x00);
        if (key.size() > block_size) {
            SHA1_CPP sha1;
            sha1.update(reinterpret_cast<const uint8_t*>(key.data()), key.size());
            sha1.finalize();
            key_padded.assign(sha1.digest().begin(), sha1.digest().end());
        }
        else {
            std::copy(key.begin(), key.end(), key_padded.begin());
        }

        std::vector<uint8_t> o_key_pad(block_size);
        std::vector<uint8_t> i_key_pad(block_size);
        for (size_t i = 0; i < block_size; ++i) {
            o_key_pad[i] = key_padded[i] ^ 0x5c;
            i_key_pad[i] = key_padded[i] ^ 0x36;
        }

        // Inner hash
        SHA1_CPP inner_sha1;
        inner_sha1.update(i_key_pad.data(), i_key_pad.size());
        inner_sha1.update(data.data(), data.size());
        inner_sha1.finalize();
        std::vector<uint8_t> inner_hash = inner_sha1.digest();

        // Outer hash
        SHA1_CPP outer_sha1;
        outer_sha1.update(o_key_pad.data(), o_key_pad.size());
        outer_sha1.update(inner_hash.data(), inner_hash.size());
        outer_sha1.finalize();
        std::vector<uint8_t> hmac = outer_sha1.digest();

        return hmac;
    }

    // Conditional HMAC-SHA1 Implementation
    std::vector<uint8_t> hmac_sha1(const std::string& key, const std::vector<uint8_t>& data) {
    #ifdef USE_OPENSSL
        // Use OpenSSL's HMAC-SHA1
        unsigned int len = SHA_DIGEST_LENGTH;
        unsigned char* result;
        std::vector<uint8_t> hmac_result(SHA_DIGEST_LENGTH);

        HMAC_CTX* ctx = HMAC_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create HMAC_CTX.");

        if (HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha1(), NULL) != 1) {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("HMAC_Init_ex failed.");
        }

        if (HMAC_Update(ctx, data.data(), data.size()) != 1) {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("HMAC_Update failed.");
        }

        if (HMAC_Final(ctx, hmac_result.data(), &len) != 1) {
            HMAC_CTX_free(ctx);
            throw std::runtime_error("HMAC_Final failed.");
        }

        HMAC_CTX_free(ctx);

        return hmac_result;
    #else
        // Use pure C++ HMAC-SHA1
        return hmac_sha1_cpp(key, data);
    #endif
    }

    // Pure C++ SHA1 Implementation
    class SHA1_CPP_Full {
    public:
        SHA1_CPP_Full() {
            reset();
        }

        void update(const uint8_t* data, size_t len) {
            sha1_cpp_.update(data, len);
        }

        void finalize() {
            sha1_cpp_.finalize();
        }

        std::vector<uint8_t> digest() const {
            return sha1_cpp_.digest();
        }

    private:
        SHA1_CPP sha1_cpp_;
    };

    // Conditional SHA1 Implementation
    class SHA1_Final {
    public:
        SHA1_Final() {
    #ifdef USE_OPENSSL
            // OpenSSL handles internal state
            // No initialization needed
    #else
            // Initialize pure C++ SHA1
            sha1_cpp_ = std::make_unique<SHA1_CPP_Full>();
    #endif
        }

        void update(const uint8_t* data, size_t len) {
    #ifdef USE_OPENSSL
            SHA1_Update(&sha1_ctx_, data, len);
    #else
            sha1_cpp_->update(data, len);
    #endif
        }

        void finalize() {
    #ifdef USE_OPENSSL
            SHA1_Final(digest_, &sha1_ctx_);
    #else
            sha1_cpp_->finalize();
        }

        std::vector<uint8_t> digest() const {
            return sha1_cpp_->digest();
    #endif
        }

    private:
    #ifdef USE_OPENSSL
        SHA_CTX sha1_ctx_;
        uint8_t digest_[20];
    #else
        std::unique_ptr<SHA1_CPP_Full> sha1_cpp_;
    #endif
    };

    // CRC32 Implementation for FINGERPRINT (Same as previous)
    uint32_t crc32(const std::vector<uint8_t>& data) {
        uint32_t crc = 0xFFFFFFFF;
        for (auto byte : data) {
            crc ^= (static_cast<uint32_t>(byte) << 24);
            for (int j = 0; j < 8; ++j) {
                if (crc & 0x80000000) {
                    crc = (crc << 1) ^ 0x04C11DB7;
                }
                else {
                    crc <<= 1;
                }
            }
        }
        return crc ^ 0xFFFFFFFF;
    }

    // Encryption Function (Placeholder)
    // Implement actual encryption as needed
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::string& key) {
        // Placeholder: XOR encryption (not secure)
        std::vector<uint8_t> encrypted(data.size());
        for (size_t i = 0; i < data.size(); ++i) {
            encrypted[i] = data[i] ^ key[i % key.size()];
        }
        return encrypted;
    }

    // Decryption Function (Placeholder)
    // Implement actual decryption as needed
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::string& key) {
        // Placeholder: XOR decryption (same as encryption)
        std::vector<uint8_t> decrypted(data.size());
        for (size_t i = 0; i < data.size(); ++i) {
            decrypted[i] = data[i] ^ key[i % key.size()];
        }
        return decrypted;
    }

} // namespace Crypt

#endif // CRYPT_HPP
