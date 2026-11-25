#include <cc/crypto/hash.hpp>
#include <cc/crypto/utils/logger.hpp>

int main()
{
    //Example for oneshot hashing. For SHAKE use Hasher::xof
    ByteArray msg = hex_to_bytes(ascii_to_hex("Hello World!"));
    PRINT("SHA1: {}", cc::crypto::Hasher::hash(msg, cc::crypto::DIGEST_MODE::SHA_1));

    //Example for HMAC
    ByteArray key = hex_to_bytes(ascii_to_hex("HelloKey!"));
    ByteArray hmacDigest = cc::crypto::Hasher::hmac(msg, key, cc::crypto::DIGEST_MODE::SHA_3_512);
    PRINT("HMAC: {}", hmacDigest);

    //Example using update + SHAKE
    cc::crypto::Hasher h(cc::crypto::DIGEST_MODE::SHA_3_SHAKE_128);
    h.update(msg);
    PRINT("Shake 72 bytes: {}", h.xof_digest(72));

    return 0;
}
