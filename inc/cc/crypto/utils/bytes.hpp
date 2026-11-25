#pragma once
#include "../export.hpp"
#include <stdio.h>
#include "cstring"
#include <vector>
#include <string>
#include <cstdint>
#include <openssl/bn.h>
#include <span>

typedef std::vector<uint8_t> ByteArray;
typedef std::span<const uint8_t> ByteSpan;

//Hex helpers
CC_CRYPTO_API std::string bytes_to_hex(const std::vector<uint8_t>& bytes, bool uppercase = false);
CC_CRYPTO_API std::string ascii_to_hex(const std::string& ascii, bool uppercase = false);
CC_CRYPTO_API std::vector<uint8_t> hex_to_bytes(const std::string& hex);
CC_CRYPTO_API std::vector<uint8_t> hex_to_bytes(const std::string& hex, size_t byteLength);
CC_CRYPTO_API BIGNUM *hex_to_bignum(const std::string &hex);
CC_CRYPTO_API void hex_to_bignum(BIGNUM *bn, const std::string &str);
CC_CRYPTO_API ByteArray ascii_to_bytearray(const std::string &ascii);

//Byte array helpers
CC_CRYPTO_API std::vector<uint8_t> byteptr_to_bytearray(uint8_t *from, size_t len);
CC_CRYPTO_API std::vector<uint8_t> char_to_bytearray(const char* buffer, size_t length);
CC_CRYPTO_API std::vector<uint8_t> bignum_to_bytearray(BIGNUM* cipherNumber, size_t maxBytes);
CC_CRYPTO_API ByteArray strip_padding(const ByteArray &input);

CC_CRYPTO_API char *print_word(uint8_t *input, size_t length, size_t blockSize);