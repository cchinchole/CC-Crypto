#pragma once
#include <openssl/bn.h>
#include <stdio.h>
#include <memory.h>
#include "cc/crypto/types.hpp"

constexpr int kSha1BlockSizeBytes = 64;
constexpr int kSha256BlockSizeBytes = 64;
constexpr int kSha512BlockSizeBytes = 128;
constexpr int kSha3Words = 25;     /* 1600/8 / sizeof(uint64_t) */

/* Shared SHA-1 / SHA-2 helpers */
inline uint64_t sha_ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
inline uint64_t sha_parity(uint64_t x, uint64_t y, uint64_t z) { return x ^ y ^ z; }
inline uint64_t sha_maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }

inline uint32_t sha_load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

inline uint64_t sha_load_be64(const uint8_t *p)
{
    return ((uint64_t)sha_load_be32(p) << 32) | sha_load_be32(p + 4);
}

inline void sha_store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

inline void sha_store_be64(uint8_t *p, uint64_t v)
{
    sha_store_be32(p, (uint32_t)(v >> 32));
    sha_store_be32(p + 4, (uint32_t)v);
}

inline uint64_t sha_load_le64(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

inline void sha_store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

inline void sha_store_le64(uint8_t *p, uint64_t v)
{
    sha_store_le32(p, (uint32_t)v);
    sha_store_le32(p + 4, (uint32_t)(v >> 32));
}

class ShaContext
{
private:
public:
    uint64_t block_cursor_ = 0;
    cc::crypto::DIGEST_MODE mode_ = cc::crypto::DIGEST_MODE::SHA_1;
    void* ph_;
    void* pmsg_len_;
    void* pblock_;
    virtual void clear() {}
    virtual ~ShaContext() {}
};

class Sha1Context : public ShaContext
{
private:
    uint64_t msglen_ = 0;
    uint32_t h_[5] = {
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
        0xc3d2e1f0};
    uint8_t block_[kSha1BlockSizeBytes];

public:
    Sha1Context();
    void clear();
};


class Sha256Context : public ShaContext
{
private:
    uint64_t msglen_ = 0;
    uint32_t h_[8];
    uint8_t block_[kSha256BlockSizeBytes];

public:
    Sha256Context(cc::crypto::DIGEST_MODE mode);
    void clear();
};

class Sha512Context : public ShaContext
{
private:
    uint64_t msglen_[2] = {0, 0};
    uint8_t block_[kSha512BlockSizeBytes];
    uint64_t h_[8];
public:
    Sha512Context(cc::crypto::DIGEST_MODE mode);
    void clear();
};

class Sha3Context : public ShaContext
{
private:
public:
    size_t digest_bytes_ = 0;
    uint32_t r_ = 0;
    uint64_t lanes_[kSha3Words];
    Sha3Context(cc::crypto::DIGEST_MODE mode);
    void clear();
};

ShaContext *sha_new_context(cc::crypto::DIGEST_MODE mode);
int get_block_length(cc::crypto::DIGEST_MODE mode);
int get_return_length(cc::crypto::DIGEST_MODE mode);
char *sha_mode_name(cc::crypto::DIGEST_MODE mode);
//void sha3_shake_digest_bytes(ShaContext *ctx_raw, size_t digestBytes);

int sha1_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx);
int sha256_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx);
int sha512_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx);
int sha3_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx);
int sha1_digest(uint8_t *digest_out, ShaContext *ctx);
int sha256_digest(uint8_t *digest_out, ShaContext *ctx);
int sha512_digest(uint8_t *digest_out, ShaContext *ctx);
int sha3_digest(uint8_t *digest_out, ShaContext *ctx);
int sha3_shake_digest(uint8_t *digestOut, size_t digestLen, ShaContext *ctx);

int sha_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx);
int sha_digest(uint8_t *digest_out, ShaContext *ctx);
