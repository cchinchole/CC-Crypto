#include "internal/sha.hpp"
#include <cstdint>
#include <cstring>

#define SHA384512_NUM_WORDS 16
#define SHA384512_ROUNDS 80
#define SHA2_512_LEN_BYTES (2 * sizeof(uint64_t))
#define SHA384512_ROTR(value, bits)                                            \
    (((value) >> (bits)) | ((value) << (sizeof(uint64_t) * 8 - (bits))))
#define SHA384512_SHR(value, bits) ((value) >> (bits))

#define SHA384512_ROUND(t)                                                     \
    do                                                                         \
    {                                                                          \
        if ((t) >= SHA384512_NUM_WORDS)                                        \
            W[(t)] = sigma1_512(W[(t) - 2]) + W[(t) - 7] +                     \
                     sigma0_512(W[(t) - 15]) + W[(t) - 16];                    \
        uint64_t tmp1 =                                                        \
            h + summat1_512(e) + sha_ch(e, f, g) + kSha384512K[(t)] + W[(t)];  \
        uint64_t tmp2 = summat0_512(a) + sha_maj(a, b, c);                     \
        h = g;                                                                 \
        g = f;                                                                 \
        f = e;                                                                 \
        e = d + tmp1;                                                          \
        d = c;                                                                 \
        c = b;                                                                 \
        b = a;                                                                 \
        a = tmp1 + tmp2;                                                       \
    } while (0)

constexpr static uint64_t kSha384512K[SHA384512_ROUNDS] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

static uint64_t summat0_512(uint64_t x)
{
    return SHA384512_ROTR(x, 28) ^ SHA384512_ROTR(x, 34) ^
           SHA384512_ROTR(x, 39);
}

static uint64_t summat1_512(uint64_t x)
{
    return SHA384512_ROTR(x, 14) ^ SHA384512_ROTR(x, 18) ^
           SHA384512_ROTR(x, 41);
}

static uint64_t sigma0_512(uint64_t x)
{
    return SHA384512_ROTR(x, 1) ^ SHA384512_ROTR(x, 8) ^ SHA384512_SHR(x, 7);
}

static uint64_t sigma1_512(uint64_t x)
{
    return SHA384512_ROTR(x, 19) ^ SHA384512_ROTR(x, 61) ^ SHA384512_SHR(x, 6);
}

static void sha512_process(uint64_t H[8], const uint8_t *block)
{
    /* Using the full message schedule in accordance to FIPS 180-4 6.4.2 */
    uint64_t W[SHA384512_ROUNDS];

    /* Step 1: Preparing the message schedule; W[16] onwards is filled in by
     * the round macro as each round needs it */
    for (int i = 0; i < SHA384512_NUM_WORDS; i++)
        W[i] = sha_load_be64(block + i * sizeof(uint64_t));

    /* Step 2: Initialize working vars */
    uint64_t a = H[0];
    uint64_t b = H[1];
    uint64_t c = H[2];
    uint64_t d = H[3];
    uint64_t e = H[4];
    uint64_t f = H[5];
    uint64_t g = H[6];
    uint64_t h = H[7];

    /* Step 3: 80 rounds */
    for (int t = 0; t < SHA384512_ROUNDS; t++)
        SHA384512_ROUND(t);

    /* Step 4: compute intermediate hash value */
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

/* Handles both SHA-384 and SHA-512; they only differ in H0 and digest size */
int sha512_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx)
{
    if (ctx == NULL || (msg == NULL && byMsg_len != 0))
        return -1;
    if (ctx->mode_ != cssl::DIGEST_MODE::SHA_512 &&
        ctx->mode_ != cssl::DIGEST_MODE::SHA_384 &&
        ctx->mode_ != cssl::DIGEST_MODE::SHA_512_224 &&
        ctx->mode_ != cssl::DIGEST_MODE::SHA_512_256)
        return -1;

    uint64_t *bMsg_len = (uint64_t *)ctx->pmsg_len_;
    uint8_t *block = (uint8_t *)ctx->pblock_;
    uint64_t *H = (uint64_t *)ctx->ph_;
    const size_t block_len = get_block_length(ctx->mode_);

    /* Make sure the bits are not exceeding 2^128. bMsg_len[0] is the low word,
     * bMsg_len[1] the high word; len >> 61 is the part of len * 8 that does not
     * fit in the low word. */
    uint64_t bits = (uint64_t)byMsg_len << 3;
    uint64_t carry = (bMsg_len[0] + bits < bits) + ((uint64_t)byMsg_len >> 61);
    if (carry > UINT64_MAX - bMsg_len[1])
        return -1;

    if (byMsg_len == 0)
        return 0;

    const uint8_t *src = msg;
    bMsg_len[0] += bits;
    bMsg_len[1] += carry;

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
        sha512_process(H, block);
        ctx->block_cursor_ = 0;
    }

    /* Whole blocks are compressed straight from the caller's buffer */
    for (; byMsg_len >= block_len; src += block_len, byMsg_len -= block_len)
        sha512_process(H, src);

    /* Buffer the tail for the next update/digest */
    memcpy(block, src, byMsg_len);
    ctx->block_cursor_ = byMsg_len;
    return 0;
}

int sha512_digest(uint8_t *digest_out, ShaContext *ctx)
{
    if (digest_out == NULL || ctx == NULL)
        return -1;
    if (ctx->mode_ != cssl::DIGEST_MODE::SHA_512 &&
        ctx->mode_ != cssl::DIGEST_MODE::SHA_384 &&
        ctx->mode_ != cssl::DIGEST_MODE::SHA_512_224 &&
        ctx->mode_ != cssl::DIGEST_MODE::SHA_512_256)
        return -1;

    uint64_t *bMsg_len = (uint64_t *)ctx->pmsg_len_;
    uint8_t *block = (uint8_t *)ctx->pblock_;
    uint64_t *H = (uint64_t *)ctx->ph_;
    const size_t block_len = get_block_length(ctx->mode_);
    size_t cursor = ctx->block_cursor_;

    /* Set the first bit to 1 (0b10000000) */
    block[cursor++] = 0x80;

    /* If the 128-bit message length no longer fits, pad out the remaining
     * block and process it first */
    if (cursor > block_len - SHA2_512_LEN_BYTES)
    {
        memset(block + cursor, 0, block_len - cursor);
        sha512_process(H, block);
        cursor = 0;
    }

    /* Zero until the length field, then append the bit length (high word
     * first) */
    memset(block + cursor, 0, block_len - SHA2_512_LEN_BYTES - cursor);
    sha_store_be64(block + block_len - SHA2_512_LEN_BYTES, bMsg_len[1]);
    sha_store_be64(block + block_len - sizeof(uint64_t), bMsg_len[0]);

    /* Process the final message */
    sha512_process(H, block);
    ctx->block_cursor_ = 0;

    /* SHA-512/224 ends on half a word, so the last partial word goes through a temp buffer */
    size_t full_words = get_return_length(ctx->mode_) / sizeof(uint64_t);
    size_t tail_bytes = get_return_length(ctx->mode_) % sizeof(uint64_t);
    for (size_t i = 0; i < full_words; i++)
        sha_store_be64(digest_out + i * sizeof(uint64_t), H[i]);
    if (tail_bytes) {
        uint8_t last[sizeof(uint64_t)];
        sha_store_be64(last, H[full_words]);
        memcpy(digest_out + full_words * sizeof(uint64_t), last, tail_bytes);
    }

    return 0;
}
