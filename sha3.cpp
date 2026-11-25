#include "internal/sha.hpp"
#include <math.h>

#define SHA3_WORDS 25
#define KECCAKF_ROUNDS 24

#define SHA3_ROTL(value, bits) (((value) << ((bits) & 63)) | ((value) >> ((64 - ((bits) & 63)) & 63))) 

/* 
 * FIPS 202 table 6.1, 6.2: 
 * SHA3 appends 0b01
 * SHAKE appends 0b1111 
 * Both still need the original padding of 0b00001
 */
#define SHA3_PADDING_SHA3 0x06
#define SHA3_PADDING_SHAKE 0x1F

/*
 * FIPS 202 3.1.2: Lanes are stored as A[x + 5y].
 * One full round (theta, rho, pi, chi) for output row y where in,out are the lanes.
 * D holds theta's column values.
 * PI: A'[x,y] = A[(x + 3y) mod 5, x], so output lane x of row y reads source lane sN rotated by rN.
 * RHO offsets are from SP202 table 2 (%64).
 * CHI: A'[x,y] = B[x,y] ^ (~B[(x+1) mod 5,y] & B[(x+2) mod 5,y])
 */
#define SHA3_ROUND_ROW(out, in, y, s0, r0, s1, r1, s2, r2, s3, r3, s4, r4)                                             \
    do {                                                                                                               \
        uint64_t b0 = SHA3_ROTL((in)[s0] ^ D[(s0) % 5], r0);                                                           \
        uint64_t b1 = SHA3_ROTL((in)[s1] ^ D[(s1) % 5], r1);                                                           \
        uint64_t b2 = SHA3_ROTL((in)[s2] ^ D[(s2) % 5], r2);                                                           \
        uint64_t b3 = SHA3_ROTL((in)[s3] ^ D[(s3) % 5], r3);                                                           \
        uint64_t b4 = SHA3_ROTL((in)[s4] ^ D[(s4) % 5], r4);                                                           \
        (out)[5 * (y) + 0] = b0 ^ (~b1 & b2);                                                                          \
        (out)[5 * (y) + 1] = b1 ^ (~b2 & b3);                                                                          \
        (out)[5 * (y) + 2] = b2 ^ (~b3 & b4);                                                                          \
        (out)[5 * (y) + 3] = b3 ^ (~b4 & b0);                                                                          \
        (out)[5 * (y) + 4] = b4 ^ (~b0 & b1);                                                                          \
    } while (0)

/*
 * Theta: C[x] = A[x,0] ^ A[x,1] ^ ... ^ A[x,4],  D[x] = C[(x-1) mod 5] ^ ROTL(C[(x+1) mod 5], 1)
 * then the rest of the round row by row, and iota: A[0,0] ^= RC
 */
#define SHA3_ROUND(out, in, round)                                                                                     \
    do {                                                                                                               \
        uint64_t C[5];                                                                                                 \
        uint64_t D[5];                                                                                                 \
        C[0] = (in)[0] ^ (in)[5] ^ (in)[10] ^ (in)[15] ^ (in)[20];                                                     \
        C[1] = (in)[1] ^ (in)[6] ^ (in)[11] ^ (in)[16] ^ (in)[21];                                                     \
        C[2] = (in)[2] ^ (in)[7] ^ (in)[12] ^ (in)[17] ^ (in)[22];                                                     \
        C[3] = (in)[3] ^ (in)[8] ^ (in)[13] ^ (in)[18] ^ (in)[23];                                                     \
        C[4] = (in)[4] ^ (in)[9] ^ (in)[14] ^ (in)[19] ^ (in)[24];                                                     \
        D[0] = C[4] ^ SHA3_ROTL(C[1], 1);                                                                              \
        D[1] = C[0] ^ SHA3_ROTL(C[2], 1);                                                                              \
        D[2] = C[1] ^ SHA3_ROTL(C[3], 1);                                                                              \
        D[3] = C[2] ^ SHA3_ROTL(C[4], 1);                                                                              \
        D[4] = C[3] ^ SHA3_ROTL(C[0], 1);                                                                              \
        SHA3_ROUND_ROW(out, in, 0, 0, 0, 6, 44, 12, 43, 18, 21, 24, 14);                                               \
        SHA3_ROUND_ROW(out, in, 1, 3, 28, 9, 20, 10, 3, 16, 45, 22, 61);                                               \
        SHA3_ROUND_ROW(out, in, 2, 1, 1, 7, 6, 13, 25, 19, 8, 20, 18);                                                 \
        SHA3_ROUND_ROW(out, in, 3, 4, 27, 5, 36, 11, 10, 17, 15, 23, 56);                                              \
        SHA3_ROUND_ROW(out, in, 4, 2, 62, 8, 55, 14, 39, 15, 41, 21, 2);                                               \
        (out)[0] ^= SHA3_RC_K[(round)];                                                                                \
    } while (0)

/* Table 1 Keccak */
static const uint64_t SHA3_RC_K[KECCAKF_ROUNDS] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b,
    0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000a, 0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

void sha3_keccakf(uint64_t lanes[SHA3_WORDS])
{
    /* Two rounds per iteration, ping-ponging between A and E so no copy is needed between rounds */
    uint64_t A[SHA3_WORDS];
    uint64_t E[SHA3_WORDS];

    memcpy(A, lanes, sizeof(A));
    for (int i = 0; i < KECCAKF_ROUNDS; i += 2) {
        SHA3_ROUND(E, A, i);
        SHA3_ROUND(A, E, i + 1);
    }
    memcpy(lanes, A, sizeof(A));
}

/* Applies the domain bits and pad10*1 at the cursor, then runs the final permutation */
void sha3_pad(Sha3Context *ctx, uint8_t domain)
{
    size_t cursor = ctx->block_cursor_;
    ctx->lanes_[cursor / 8] ^= (uint64_t)domain << (8 * (cursor % 8));

    /* r is a multiple of 8, so byte r - 1 is the top byte of lane r/8 - 1 */
    ctx->lanes_[ctx->r_ / 8 - 1] ^= (uint64_t)0x80 << 56;
    sha3_keccakf(ctx->lanes_);
    ctx->block_cursor_ = 0;
}

/* Reads len bytes out of the sponge, permuting whenever a block of r bytes has been used */
static void sha3_squeeze(Sha3Context *ctx, uint8_t *output, size_t len)
{
    size_t cursor = ctx->block_cursor_;
    size_t i = 0;

    while (i < len) {
        if (cursor >= ctx->r_) {
            sha3_keccakf(ctx->lanes_);
            cursor = 0;
        }
        if (cursor % 8 == 0 && len - i >= 8) {
            sha_store_le64(output + i, ctx->lanes_[cursor / 8]);
            cursor += 8;
            i += 8;
        } else {
            output[i++] = (uint8_t)(ctx->lanes_[cursor / 8] >> (8 * (cursor % 8)));
            cursor++;
        }
    }
    ctx->block_cursor_ = cursor;
}

int sha3_update(const uint8_t *msg, size_t byMsg_len, ShaContext *ctx_raw)
{
    Sha3Context *ctx = (Sha3Context*)ctx_raw;
    if (byMsg_len == 0)
        return 0;
    if (msg==NULL && byMsg_len != 0)
        return -1;
    
    size_t cursor = ctx->block_cursor_;
    size_t i = 0;

    /* Whole lanes are absorbed when the cursor is lane aligned, otherwise one byte at a time */
    while (i < byMsg_len) {
        if (cursor % 8 == 0 && byMsg_len - i >= 8) {
            ctx->lanes_[cursor / 8] ^= sha_load_le64(msg + i);
            cursor += 8;
            i += 8;
        } else {
            ctx->lanes_[cursor / 8] ^= (uint64_t)msg[i++] << (8 * (cursor % 8));
            cursor++;
        }
        if (cursor >= ctx->r_) {
            sha3_keccakf(ctx->lanes_);
            cursor = 0;
        }
    }
    ctx->block_cursor_ = cursor;
    return 0;
}

int sha3_digest(uint8_t *digestOut, ShaContext *ctx_raw)
{
    if (ctx_raw == NULL)
        return -1;

    Sha3Context *ctx = (Sha3Context*)ctx_raw;

    /* This is a check for SHAKE functions being passed */
    if (ctx->digest_bytes_ == 0)
        return -1;

    if (digestOut == NULL)
        return -1;

    /* Padding and setting the last bits to 11 */
    sha3_pad(ctx, SHA3_PADDING_SHA3);
    sha3_squeeze(ctx, digestOut, ctx->digest_bytes_);
    return 0;
}

int sha3_shake_digest(uint8_t *digestOut, size_t digestLen, ShaContext *ctx_raw)
{
    if (digestOut == NULL || ctx_raw == NULL || digestLen == 0)
        return -1; 

    Sha3Context *ctx = (Sha3Context*)ctx_raw;

    sha3_pad(ctx, SHA3_PADDING_SHAKE);
    sha3_squeeze(ctx, digestOut, digestLen);
    return 0;
}
