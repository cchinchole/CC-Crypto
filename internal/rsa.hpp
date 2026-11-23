#pragma once
#include "cc/crypto/utils/bytes.hpp"
#include "cc/crypto/types.hpp"
#include <openssl/bn.h>

// These classes are purely internal no reason to export them.
enum class RsaPadding{
    OAEP,
    NONE
};

struct RsaPaddingParams {
    RsaPadding mode;
    cc::crypto::DIGEST_MODE label_hash_mode;
    cc::crypto::DIGEST_MODE hask_hash_mode;
    ByteArray label;
    ByteArray seed;
};

class RsaCrtParams {
public:
    BIGNUM *dp_; 
    BIGNUM *dq_;
    BIGNUM *qinv_;
    BIGNUM *p_; 
    BIGNUM *q_;
    bool enabled_ = false;
    RsaCrtParams();
    ~RsaCrtParams();
};

class RsaKey {
public:
    int modulus_bits_ = 4096; 
    BIGNUM* n_;
    BIGNUM* e_;
    BIGNUM* d_;
    RsaCrtParams crt_params_;
    RsaPaddingParams padding_;
    void reset_padding();
    RsaKey();
   ~RsaKey();
};
int rsa_pairwise_test(RsaKey& key);
int rsa_gen_crt_params(RsaKey& key, bool constTime);
void rsa_generate_key(RsaKey& key, int kBits);
void rsa_add_oaep(RsaKey& key, ByteSpan label, ByteSpan seed, cc::crypto::DIGEST_MODE hashMode, cc::crypto::DIGEST_MODE maskHashMode);
void rsa_add_oaep(RsaKey& key, ByteSpan label, cc::crypto::DIGEST_MODE hashMode, cc::crypto::DIGEST_MODE maskHashMode);
ByteArray rsa_encrypt(RsaKey& key, std::span<const uint8_t> src);
ByteArray rsa_decrypt(RsaKey& key, std::span<const uint8_t> cipher);
ByteArray rsa_mgf1(std::span<const uint8_t> seed, size_t maskLen, cc::crypto::DIGEST_MODE shaMode = cc::crypto::DIGEST_MODE::SHA_1);
