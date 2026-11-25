#pragma once

// Marks a symbol as part of the public ABI of libcssl.so. The library is
// built with -fvisibility=hidden, so anything not tagged stays internal.
#define CC_CRYPTO_API __attribute__((visibility("default")))
