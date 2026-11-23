#include "cc/crypto/primes.hpp"
#include "../internal/primes.hpp"

namespace cc::crypto
{
bool check_if_prime(BIGNUM *w)
{
    return check_prime(w);
}
void gen_primes(BIGNUM *p, BIGNUM *q, BIGNUM *e, int bits)
{
    fips186_4_gen_primes(p, q, e, bits, false, NULL);
}
}
