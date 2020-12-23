#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "./../errors.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <string.h>


typedef unsigned char byte;

// Output size of SHA256.
static const int SHA256_OUTPUT_BYTES = 32;
static const int PRF_OUTPUT_BYTES = 32;

/**
 * Evaluates the PRF given input (as byte arrays), storing
 * the result in a destination byte array.
 *
 * @param dst    sha-256结果保存的位置
 * @param dstlen 结果的byte arrays大小
 * @param src    输入
 * @param srclen 输入的byte arrays大小
 *
 * @return ERROR_NONE on success, ERROR_DSTLEN_INVALID if the destination size
 *         is invalid
 */
int sha_256(byte* dst, uint32_t dstlen, byte* src, uint32_t srclen);

/**
 * Evaluates the PRF given a key and input (as byte arrays), storing
 * the result in a destination byte array.
 *
 * @param dst    The destination byte array that will contain the output of the PRF
 * @param dstlen The size of the destination byte array
 * @param key    The PRF key
 * @param src    The byte array containing the input to the PRF
 * @param srclen The size of the input byte array
 *
 * @return ERROR_NONE on success, ERROR_DSTLEN_INVALID if the destination size
 *         is invalid
 */
int HMAC_SHA256(byte* dst, uint32_t dstlen, byte* key, byte* src, uint32_t srclen);

// TEST 输出不同长度的byte* 使用的时候需要传入&类型参数
void printf_bin_8(unsigned char* num);
// TEST


#endif /* __CRYPTO_H__ */