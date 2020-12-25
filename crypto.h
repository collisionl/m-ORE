#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "errors.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>


typedef unsigned char byte;

// Output size of SHA256 set to 32 for test.
static const int SHA256_OUTPUT_BYTES = 32;

/**
 * Evaluates the PRF given input (as byte arrays), storing
 * the result in a destination byte array.
 *
 * @param dst    result of sha-256
 * @param dstlen size of the result byte arrays
 * @param src    input
 * @param srclen size of the input byte arrays
 *
 * @return ERROR_NONE on success, ERROR_DSTLEN_INVALID if the destination size
 *         is invalid
 */
int sha_256(byte* dst, uint32_t dstlen, byte* src, uint32_t srclen);

#endif /* __CRYPTO_H__ */