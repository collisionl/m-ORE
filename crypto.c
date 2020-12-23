#include "crypto.h"
#include "errors.h"

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

  // TEST 输出参数
  // printf("sha输出大小：%ld\n",dstlen); /* 32 byte的标准输出 */
  // printf_bin_8(&src); /* 这个值不对 */
  // printf("\nsha输入开始\n");
  // printf_bin_8(&src[0]);
  // printf_bin_8(&src[1]);
  // printf_bin_8(&src[2]);
  // printf_bin_8(&src[3]);
  // printf_bin_8(&src[4]);
  // printf_bin_8(&src[5]);
  // printf_bin_8(&src[6]);
  // printf_bin_8(&src[7]);
  // printf("sha输入结束\n");
  // TEST

  // printf("\nsha输出开始\n");
  // printf_bin_8(&dst[0]);
  // printf_bin_8(&dst[1]);
  // printf_bin_8(&dst[2]);
  // printf_bin_8(&dst[3]);
  // printf_bin_8(&dst[4]);
  // printf("sha输出结束\n");

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