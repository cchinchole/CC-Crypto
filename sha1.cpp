#include "internal/sha.hpp"
#include <cstdint>
#include <cstring>

#define SHA1_DIGEST_SIZE 20
#define SHA1_NUM_WORDS 16
#define SHA1_ROUNDS 80
#define SHA1_LEN_BYTES sizeof(uint64_t)
#define SHA1_ROTL(value, bits)                                                 \
    (((value) << (bits)) | ((value) >> (sizeof(uint32_t) * 8 - (bits))))

#define SHA1_ROUND(f, k, t)                                                    \
    do                                                                         \
    {                                                                          \
        if ((t) >= SHA1_NUM_WORDS)                                             \
            W[(t)] = SHA1_ROTL(W[(t) - 3] ^ W[(t) - 8] ^ W[(t) - 14] ^         \
                                   W[(t) - 16],                                \
                               1);                                             \
        uint32_t tmp = SHA1_ROTL(a, 5) + (uint32_t)(f) + e + (k) + W[(t)];     \
        e = d;                                                                 \
        d = c;                                                                 \
        c = SHA1_ROTL(b, 30);                                                  \
        b = a;                                                                 \
        a = tmp;                                                               \
    } while (0)

static void sha1_process(uint32_t H[5], const uint8_t *block)
{
    /* Using the full message schedule in accordance to FIPS 180-4 6.1.2 */
    uint32_t W[SHA1_ROUNDS];

    /* Step 1: Preparing the message schedule; W[16] onwards is filled in by
     * the round macro as each round needs it */
    for (int i = 0; i < SHA1_NUM_WORDS; i++)
        W[i] = sha_load_be32(block + i * sizeof(uint32_t));

    /* Step 2: Initialize working vars */
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];

    /* Step 3: 80 rounds, split by f()/K so there is no per-round branching */
    for (int t = 0; t < 20; t++)
        SHA1_ROUND(sha_ch(b, c, d), 0x5a827999, t);
    for (int t = 20; t < 40; t++)
        SHA1_ROUND(sha_parity(b, c, d), 0x6ed9eba1, t);
    for (int t = 40; t < 60; t++)
        SHA1_ROUND(sha_maj(b, c, d), 0x8f1bbcdc, t);
    for (int t = 60; t < 80; t++)
        SHA1_ROUND(sha_parity(b, c, d), 0xca62c1d6, t);

    /* Step 4: compute intermediate hash value */
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
}

int sha1_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx)
{
    if (ctx == NULL || (msg == NULL && byMsg_len != 0))
        return -1;

    uint64_t *bMsg_len = (uint64_t *)ctx->pmsg_len_;
    uint8_t *block = (uint8_t *)ctx->pblock_;
    uint32_t *H = (uint32_t *)ctx->ph_;
    const size_t block_len = get_block_length(ctx->mode_);

    /* Make sure the bits are not exceeding 2^64 */
    if (byMsg_len > (UINT64_MAX - *bMsg_len) / 8)
        return -1;

    if (byMsg_len == 0)
        return 0;

    const uint8_t *src = msg;
    *bMsg_len += (uint64_t)byMsg_len * 8;

    /* Finish a partially filled block first */
    if (ctx->block_cursor_ > 0)
    {
        size_t n = block_len - ctx->block_cursor_;
        if (n > byMsg_len)
            n = byMsg_len;
        memcpy(block + ctx->block_cursor_, src, n);
        ctx->block_cursor_ += n;
        src += n;
        byMsg_len -= n;
        if (ctx->block_cursor_ < block_len)
            return 0;
        sha1_process(H, block);
        ctx->block_cursor_ = 0;
    }

    /* Whole blocks are compressed straight from the caller's buffer */
    for (; byMsg_len >= block_len; src += block_len, byMsg_len -= block_len)
        sha1_process(H, src);

    /* Buffer the tail for the next update/digest */
    memcpy(block, src, byMsg_len);
    ctx->block_cursor_ = byMsg_len;
    return 0;
}

int sha1_digest(uint8_t *digest_out, ShaContext *ctx)
{
    if (digest_out == NULL || ctx == NULL)
        return -1;

    uint64_t *bMsg_len = (uint64_t *)ctx->pmsg_len_;
    uint8_t *block = (uint8_t *)ctx->pblock_;
    uint32_t *H = (uint32_t *)ctx->ph_;
    const size_t block_len = get_block_length(ctx->mode_);
    size_t cursor = ctx->block_cursor_;

    /* Set the first bit to 1 (0b10000000) */
    block[cursor++] = 0x80;

    /* If the 64-bit message length no longer fits, pad out the remaining block
     * and process it first */
    if (cursor > block_len - SHA1_LEN_BYTES)
    {
        memset(block + cursor, 0, block_len - cursor);
        sha1_process(H, block);
        cursor = 0;
    }

    /* Zero until the length field, then append the bit length */
    memset(block + cursor, 0, block_len - SHA1_LEN_BYTES - cursor);
    sha_store_be64(block + block_len - SHA1_LEN_BYTES, *bMsg_len);

    /* Process the final message */
    sha1_process(H, block);
    ctx->block_cursor_ = 0;

    for (size_t i = 0; i < SHA1_DIGEST_SIZE / sizeof(uint32_t); i++)
        sha_store_be32(digest_out + i * sizeof(uint32_t), H[i]);
    return 0;
}
