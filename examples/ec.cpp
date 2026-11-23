#include <cc/crypto/ec.hpp>
#include <cc/crypto/utils/logger.hpp>
#include <openssl/bn.h>

int main()
{
    cc::crypto::Ec keypair = cc::crypto::Ec::generate_key(cc::crypto::EC_GROUP::P256);
    cc::crypto::Ec keypair2 = cc::crypto::Ec::generate_key(cc::crypto::EC_GROUP::P256);

    ByteArray message = {'h', 'e', 'l', 'l', 'o'};
    ByteArray message2 = {'h', 'e', 'l', 'l', 'a'};
    cc::crypto::EcSignature sig = keypair.sign(message, cc::crypto::DIGEST_MODE::SHA_256);
    cc::crypto::EcSignature sig2 = keypair.sign(message2, cc::crypto::DIGEST_MODE::SHA_256);
    cc::crypto::EcSignature sig3 = keypair2.sign(message, cc::crypto::DIGEST_MODE::SHA_256);
    cc::crypto::EcSignature sig4 = keypair.sign(message, cc::crypto::DIGEST_MODE::SHA_512);
    bool valid = keypair.verify(sig, message, cc::crypto::DIGEST_MODE::SHA_256);

    PRINT("Status of signature 1: {} expected true", valid); //Valid signature
    PRINT("Status of signature 2: {} expected false", keypair.verify(sig2, message, cc::crypto::DIGEST_MODE::SHA_256)); //Incorrect message
    PRINT("Status of signature 3: {} expected false", keypair.verify(sig3, message, cc::crypto::DIGEST_MODE::SHA_256)); //Incorrect keypair
    PRINT("Status of signature 4: {} expected false", keypair.verify(sig4, message, cc::crypto::DIGEST_MODE::SHA_256)); //Hashing mismatch
    return valid ? 0 : 1;
}
