#pragma once
#include <openssl/bn.h>

namespace cc::crypto
{
bool check_if_prime(BIGNUM *w);
void gen_primes(BIGNUM *p, BIGNUM *q, BIGNUM *e, int bits);
}
