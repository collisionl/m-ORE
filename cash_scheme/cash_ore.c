#include "crypto.h"
#include "./../errors.h"
#include "cash_ore.h"

#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>

// For permutation
typedef struct {
  uint32_t index;
  uint32_t rando;
} rand_permute[1];

// For qsort funtion
int comp(const void *p1, const void *p2) {
  rand_permute *c = (rand_permute *)p1;
  rand_permute *d = (rand_permute *)p2;
  return ((*(rand_permute *)c)->rando - (*(rand_permute *)d)->rando);
}

int init_ore_params(ore_params params, uint32_t nbits) {
  params->initialized = true;
  params->nbits = nbits;

  return ERROR_NONE;
}

int init_pairing(pairing_t pairing, element_t g1, element_t g2) {
  char param[1024];
  size_t count = fread(param, 1, 1024, stdin);
  if (!count) {
    pbc_die("input error");
    return ERROR_PAIRING_NOT_INITIALIZED;
    }
  pairing_init_set_buf(pairing, param, count);
  if (pairing_is_symmetric(pairing)) {return ERROR_PAIRING_IS_SYMMETRIC;}

  element_init_G1(g1, pairing);
  element_random(g1);
  element_init_G2(g2, pairing);
  element_random(g2);

  return ERROR_NONE;
}

int init_ore_ciphertext(ore_ciphertext ctxt, ore_params params,\
                        pairing_t pairing) {
  if (ctxt == NULL || params == NULL) {
    return ERROR_NULL_POINTER;
  }

  memcpy(ctxt->params, params, sizeof(ore_params));
  uint32_t nbits = ctxt->params->nbits;
  for (uint32_t i = 0; i < nbits; i++) {
    element_init_G1(ctxt->cipher[i]->cipher_a, pairing);
    element_init_G1(ctxt->cipher[i]->cipher_b, pairing);
    element_init_G2(ctxt->cipher[i]->cipher_c, pairing);
    element_init_G2(ctxt->cipher[i]->cipher_d, pairing);
  }

  ctxt->initialized = true;
  return ERROR_NONE;
}


/**
 * Real main function which performs the encryption of an input, storing the result
 * in a ciphertext.
 *
 * @param ctxt    The ciphertext to store the encryption
 * @param buf     The input in a byte array, encoded in little-endian
 * @param buflen  The length of the byte array input
 * @param k       The data key
 *
 * @return ERROR_NONE on success
 */
static int _ore_encryption(ore_ciphertext ctxt, byte *buf, uint32_t buflen,\
                           pairing_t pairing, element_t k, element_t g1, element_t g2) {
  if (!ctxt->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }

  uint32_t nbits = ctxt->params->nbits;

  // 密文字节, 32的nbits情况下是4byte
  uint32_t nbytes = (nbits + 7) / 8;
  
  // 生成了大小为8 byte数组, 并把这个数组每一个元素都赋为10进制的0, 每一个byte赋为0
  byte prf_input_buf[sizeof(uint32_t) + nbytes];
  memset(prf_input_buf, 0, sizeof(prf_input_buf));

  // 4byte大小的消息buf
  byte msgbuf[nbytes];
  // 设置32大小的byte类型数组来存储sha的输出
  byte prf_output_buf[SHA256_OUTPUT_BYTES];
  byte prf_input_buf_2[SHA256_OUTPUT_BYTES];
  byte key[SHA256_OUTPUT_BYTES];
  memset(key, 0, sizeof(key));
  element_to_bytes(key, k);
  // printf_bin_8(&key[0]);
  // drop any extra bytes that have been provided
  if (buflen >= nbytes) {
    memcpy(msgbuf, buf, nbytes);
  }
  else {
    memcpy(msgbuf, buf, buflen);
  }

  mpz_t SHA_to_mpz;
  mpz_init(SHA_to_mpz);
  mpz_t SHA_256_MAX;
  mpz_init(SHA_256_MAX);
  mpz_init_set_str(SHA_256_MAX, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
                   FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",16);


  // 存储prf的最后结果
  element_t prf_result;
  element_init_Zr(prf_result, pairing);


  // index的值代表prf_input_buf[0]的值
  uint32_t *index = (uint32_t *)prf_input_buf;

  // value[0] == prf_input_buf[sizeof(uint32_t)] == prf_input_buf[4]
  // 最大支持2^8-1, 256bit长的数据
  byte *value = &prf_input_buf[sizeof(uint32_t)];

  // 计算偏移
  uint32_t offset = (8 - (nbits % 8)) % 8;

  // 定义一个数组, 给index顺序赋值, rando随机赋值,
  // 随后给rando排序就得到打乱的index, 每次传入index作为此轮的存储位置
  rand_permute *permute = (rand_permute *)malloc(sizeof(rand_permute) * nbits);
  for (uint32_t i = 0; i < nbits; i++) {
    permute[i]->index = i;
    permute[i]->rando = rand();
  }
  qsort(permute, nbits, sizeof(permute), comp);

  for (uint32_t i = 0; i < nbits; i++) {
    // init cipher a and c using random number
    element_t r1, r2;
    element_init_Zr(r1, pairing);
    element_init_Zr(r2, pairing);
    element_random(r1);
    element_random(r2);
    element_pow_zn(ctxt->cipher[permute[i]->index]->cipher_a, g1, r1);
    element_pow_zn(ctxt->cipher[permute[i]->index]->cipher_c, g2, r2);

    // get the current bit of the message
    // 因为是小端序, 每次加密先算好这次加密的密文在msgbuf的哪个位置
    uint32_t byteind = nbytes - 1 - (i + offset) / 8;

    // mask表示这一个byte中对应位置的比特密文的二进制值是不是1
    byte mask = msgbuf[byteind] & (1 << ((7 - (i + offset)) % 8));

    // 每次prf_input_buf[0]是新的i的值, 从0开始
    sha_256(prf_output_buf, sizeof(prf_output_buf),
            prf_input_buf, sizeof(prf_input_buf));

    // 把第一次的输出作为第二次的输入
    memcpy(prf_input_buf_2, prf_output_buf, 32);

    if (mask > 0) {
      mpz_import(SHA_to_mpz, 32, 1, 1, -1, 0, prf_output_buf);
      mpz_add_ui(SHA_to_mpz, SHA_to_mpz, 1);
      mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
      mpz_export(prf_input_buf_2, NULL, 1, 1, -1, 0, SHA_to_mpz);
    }

    HMAC_SHA256(prf_output_buf, sizeof(prf_output_buf), key,
            prf_input_buf_2, sizeof(prf_input_buf_2));

    element_from_hash(prf_result, prf_output_buf, 32);
    element_pow_zn(ctxt->cipher[permute[i]->index]->cipher_b, ctxt->cipher[permute[i]->index]->cipher_a, prf_result);

    mpz_import(SHA_to_mpz, 32, 1, 1, -1, 0, prf_input_buf_2);
    mpz_add_ui(SHA_to_mpz, SHA_to_mpz, 1);
    mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
    mpz_export(prf_input_buf_2, NULL, 1, 1, -1, 0, SHA_to_mpz);

    // 计算第二次hash并用结果生成Zr中元素以用在后面的模指数运算中, 覆盖第一次prf运算的结果
    HMAC_SHA256(prf_output_buf, sizeof(prf_output_buf), key,
            prf_input_buf_2, sizeof(prf_input_buf_2));

    // 从hash的结果转到Zr上
    element_from_hash(prf_result, prf_output_buf, 32);
    element_pow_zn(ctxt->cipher[permute[i]->index]->cipher_d, ctxt->cipher[permute[i]->index]->cipher_c, prf_result);
  
    // add the current bit of the message to the running prefix
    value[byteind] |= mask;

    // increment the index for the next iteration of the loop
    (*index)++;
    element_clear(r1);
    element_clear(r2);
  }

  free(permute);
  mpz_clear(SHA_to_mpz);
  mpz_clear(SHA_256_MAX);
  element_clear(prf_result);

  return ERROR_NONE;
}

int ore_encryption(ore_ciphertext ctxt, uint64_t msg, pairing_t pairing,\
                   element_t k, element_t g1, element_t g2) {
  return _ore_encryption(ctxt, (byte *)&msg, sizeof(msg), pairing, k, g1, g2);
}

int ore_compare(int *result_p, ore_ciphertext ctxt1, ore_ciphertext ctxt2, pairing_t pairing) {
  // 首先检查两个长度是否相等, 是否都初始化过了
  if ((ctxt1->params->initialized != ctxt2->params->initialized) ||
      (ctxt1->params->nbits != ctxt2->params->nbits)) {
    return ERROR_PARAMS_MISMATCH;
  }
  if(!ctxt1->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }
  if(!ctxt2->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }

  int res = 0;

  element_t temp1, temp2, temp3, temp4;
  element_init_GT(temp1, pairing);
  element_init_GT(temp2, pairing);
  element_init_GT(temp3, pairing);
  element_init_GT(temp4, pairing);

  uint32_t nbits = ctxt1->params->nbits;
  bool break_flag = false;
  
  for (uint32_t i = 0; i < nbits; i++) {
    for (uint32_t j = 0; j < nbits; j++) {
      pairing_apply(temp1, ctxt1->cipher[i]->cipher_a, ctxt2->cipher[j]->cipher_d, pairing);
      pairing_apply(temp2, ctxt1->cipher[i]->cipher_b, ctxt2->cipher[j]->cipher_c, pairing);
      pairing_apply(temp3, ctxt2->cipher[j]->cipher_b, ctxt1->cipher[i]->cipher_c, pairing);
      pairing_apply(temp4, ctxt2->cipher[j]->cipher_a, ctxt1->cipher[i]->cipher_d, pairing);
      if (!element_cmp(temp1, temp2)) {
        res = 1;
        break_flag = true;
        break;
      }
      if (!element_cmp(temp3, temp4)) {
        res = -1;
        break_flag = true;
        break;
      }
    }
    if (break_flag)
      break;
  }

  *result_p = res;
  element_clear(temp1);
  element_clear(temp2);
  element_clear(temp3);
  element_clear(temp4);
  return ERROR_NONE;
}

int clear_ore_ciphertext(ore_ciphertext ctxt) {
  if (ctxt == NULL) {
    return ERROR_NONE;
  }
  uint32_t nbits = ctxt->params->nbits;
  for (uint32_t i = 0; i < nbits; i++) {
    element_clear(ctxt->cipher[i]->cipher_a);
    element_clear(ctxt->cipher[i]->cipher_b);
    element_clear(ctxt->cipher[i]->cipher_c);
    element_clear(ctxt->cipher[i]->cipher_d);
  }

  return ERROR_NONE;
}

int clear_pairing(pairing_t pairing, element_t g1, element_t g2) {
  // Pairing must be the last one to be cleared.
  element_clear(g1);
  element_clear(g2);
  pairing_clear(pairing);

  return ERROR_NONE;
}