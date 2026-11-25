#pragma once
#include "export.hpp"
#include <openssl/bn.h>

namespace cc::crypto
{
CC_CRYPTO_API bool check_if_prime(BIGNUM *w);
CC_CRYPTO_API void gen_primes(BIGNUM *p, BIGNUM *q, BIGNUM *e, int bits);
}
