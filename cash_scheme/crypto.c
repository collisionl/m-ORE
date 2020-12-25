#include "crypto.h"
#include "./../errors.h"

#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>

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

// HMAC_SHA256 as the hmac
int HMAC_SHA256(byte* dst, uint32_t dstlen, byte* key, byte* src, uint32_t srclen) {
  if (dstlen != PRF_OUTPUT_BYTES) {
    return ERROR_DSTLEN_INVALID;
  }

  uint32_t outlen;
  HMAC(EVP_sha256(), key, sizeof(key), src, srclen, dst, &outlen);

  return ERROR_NONE;
}