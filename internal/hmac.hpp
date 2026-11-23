#pragma once
#include "cc/crypto/types.hpp"
#include "cc/crypto/utils/bytes.hpp"
void hmacFinalize(cc::crypto::DIGEST_MODE digestMode, uint8_t* hmac_out,
             ByteSpan msg, ByteSpan key);
