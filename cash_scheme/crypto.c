#include "crypto.h"
#include "./../errors.h"

#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>

// 新方案里不需要带密钥的hmac，只用sha-256就够了
int sha_256(byte* dst, uint32_t dstlen, byte* src, uint32_t srclen) {
  if (dstlen != SHA256_OUTPUT_BYTES) {
    return ERROR_DSTLEN_INVALID;
  }

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, src, srclen);
  SHA256_Final(dst, &ctx); 
  
  return ERROR_NONE;
}

int HMAC_SHA256(byte* dst, uint32_t dstlen, byte* key, byte* src, uint32_t srclen) {
  if (dstlen != PRF_OUTPUT_BYTES) {
    return ERROR_DSTLEN_INVALID;
  }

  uint32_t outlen;
  HMAC(EVP_sha256(), key, sizeof(key), src, srclen, dst, &outlen);

  return ERROR_NONE;
}

// TEST 输出一个byte
void printf_bin_8(unsigned char* num)
{
    for (int k = 7; k >= 0; k--) //处理8个位
    {
        if (*num & (1 << k))
            printf("1");
        else
            printf("0");
    }
    printf("\r\n");
}
// TEST