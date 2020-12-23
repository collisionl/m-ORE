#include "crypto.h"
#include "errors.h"
#include "ore.h"

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
                        pairing_t pairing, element_t g1) {
  if (ctxt == NULL || params == NULL) {
    return ERROR_NULL_POINTER;
  }

  memcpy(ctxt->params, params, sizeof(ore_params));
  uint32_t nbits = ctxt->params->nbits;
  for (uint32_t i = 0; i < nbits; i++) {
    element_init_G1(ctxt->bit_ctxt[i], pairing);
  }
  
  element_t r1;
  element_init_Zr(r1, pairing);
  element_random(r1);
  element_init_G1(ctxt->g1r1, pairing);
  element_pow_zn(ctxt->g1r1, g1, r1);

  ctxt->initialized = true;
  return ERROR_NONE;
}

int init_ore_token(ore_token token, ore_params params, pairing_t pairing,\
                   element_t g2) {
  if (token == NULL || params == NULL) {
    return ERROR_NULL_POINTER;
  }

  memcpy(token->params, params, sizeof(ore_params));
  uint32_t nbits = token->params->nbits;
  for (uint32_t i = 0; i < nbits; i++) {
    element_init_G2(token->token_bit[i]->add_one, pairing);
    element_init_G2(token->token_bit[i]->minus_one, pairing);
  }
  
  element_t r2;
  element_init_Zr(r2, pairing);
  element_init_G2(token->g2r2, pairing);
  element_random(r2);
  element_pow_zn(token->g2r2, g2, r2);

  token->initialized = true;
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
                           pairing_t pairing, element_t k) {
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

  // 先计算好, 后面直接用
  element_t g1r1k;
  element_init_G1(g1r1k, pairing);
  element_pow_zn(g1r1k, ctxt->g1r1, k);


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

#ifdef RANDOM_PERMUTE
  // 定义一个数组, 给index顺序赋值, rando随机赋值,
  // 随后给rando排序就得到打乱的index, 每次传入index作为此轮的存储位置
  rand_permute *permute = (rand_permute *)malloc(sizeof(rand_permute) * nbits);
  for (uint32_t i = 0; i < nbits; i++) {
    permute[i]->index = i;
    permute[i]->rando = rand();
  }
  qsort(permute, nbits, sizeof(permute), comp);
#endif

  for (uint32_t i = 0; i < nbits; i++) {
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

    // 如果这一比特是1, 就转成mpz_t再加1然后模2 ^ 256 - 1, 然后再转换为byte类型作为第二次的输入
    if (mask > 0) {
      mpz_import(SHA_to_mpz, 32, 1, 1, -1, 0, prf_output_buf);
      mpz_add_ui(SHA_to_mpz, SHA_to_mpz, 1);
      mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
      mpz_export(prf_input_buf_2, NULL, 1, 1, -1, 0, SHA_to_mpz);
    }

    // 计算第二次hash并用结果生成Zr中元素以用在后面的模指数运算中, 覆盖第一次prf运算的结果
    sha_256(prf_output_buf, sizeof(prf_output_buf),
            prf_input_buf_2, sizeof(prf_input_buf_2));

    // 从hash的结果转到Zr上
    element_from_hash(prf_result, prf_output_buf, 32);

#ifdef RANDOM_PERMUTE
    element_pow_zn(ctxt->bit_ctxt[permute[i]->index], g1r1k, prf_result);
#else
    element_pow_zn(ctxt->bit_ctxt[i], g1r1k, prf_result);
#endif

  
    // add the current bit of the message to the running prefix
    value[byteind] |= mask;

    // increment the index for the next iteration of the loop
    (*index)++;
  }
#ifdef RANDOM_PERMUTE
  free(permute);
#endif
  mpz_clear(SHA_to_mpz);
  mpz_clear(SHA_256_MAX);
  element_clear(g1r1k);
  element_clear(prf_result);

  return ERROR_NONE;
}

int ore_encryption(ore_ciphertext ctxt, uint64_t msg, pairing_t pairing,\
                   element_t k) {
  return _ore_encryption(ctxt, (byte *)&msg, sizeof(msg), pairing, k);
}

/**
 * Real main function which performs the token gen of an input, storing the result
 * in token.
 *
 * This function implements the encrypt algorithm for order revealing
 * encryption, using the secret key and input passed in and storing the
 * resulting ciphertext in ctxt.
 *
 * @param token    The ciphertext to store the encryption
 * @param buf      The input in a byte array, encoded in little-endian
 * @param buflen   The length of the byte array input
 * @param k        The data key
 *
 * @return ERROR_NONE on success
 */
static int _ore_token_gen(ore_token token, byte *buf, uint32_t buflen,\
                          pairing_t pairing, element_t k) {
  if (!token->initialized) {
    return ERROR_TOKEN_NOT_INITIALIZED;
  }

  uint32_t nbits = token->params->nbits;

  // 密文字节, 32的nbits情况下是4byte
  uint32_t nbytes = (nbits + 7) / 8;

  // 生成了大小为8 byte数组, 并把这个数组每一个元素都赋为10进制的0, 每一个byte赋为0,
  // 为什么使用uint32_t的大小存index
  byte prf_input_buf[sizeof(uint32_t) + nbytes];
  memset(prf_input_buf, 0, sizeof(prf_input_buf));

  byte msgbuf[nbytes];
  byte prf_output_buf[SHA256_OUTPUT_BYTES];
  byte prf_input_buf_2[SHA256_OUTPUT_BYTES];

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
  mpz_init_set_str (SHA_256_MAX, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
                                  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

  // 先计算好, 后面直接用
  element_t g2r2k;
  element_init_G2(g2r2k, pairing);
  element_pow_zn(g2r2k, token->g2r2, k);

  // 暂存prf的最后结果
  element_t prf_result;
  element_init_Zr(prf_result, pairing);

  // index的值代表prf_input_buf[0]的值
  uint32_t *index = (uint32_t *)prf_input_buf;

  // value[0] == prf_input_buf[sizeof(uint32_t)] == prf_input_buf[4]
  // 最大支持2^8-1, 256bit的数据, 因为index只有8bit的存储空间
  byte *value = &prf_input_buf[sizeof(uint32_t)];

  // 计算偏移
  uint32_t offset = (8 - (nbits % 8)) % 8;

#ifdef RANDOM_PERMUTE
  rand_permute *permute = (rand_permute *)malloc(sizeof(rand_permute) * nbits);
  for (uint32_t i = 0; i < nbits; i++) {
    permute[i]->index = i;
    permute[i]->rando = rand();
  }
  qsort(permute, nbits, sizeof(permute), comp);
#endif

  for (uint32_t i = 0; i < nbits; i++) {
    // get the current bit of the message
    uint32_t byteind = nbytes - 1 - (i + offset) / 8;

    // mask表示这一个byte中对应位置的比特密文的二进制值是不是1
    byte mask = msgbuf[byteind] & (1 << ((7 - (i + offset)) % 8));

    // 每次prf_input_buf[0]是新的i的值, 从0开始
    sha_256(prf_output_buf, sizeof(prf_output_buf),
            prf_input_buf, sizeof(prf_input_buf));

    // 如果这一比特是1, 就转成mpz_t再加2然后模2 ^ 256 - 1, 然后再转换为byte类型作为第二次的输入
    if (mask > 0) {
      // 先处理-1的部分, 就等于是加一后加一, 等于不运算,
      // 直接把上个sha的输出作为下次输入再sha一次, 得到输出后转Zr的元素直接算
      memcpy(prf_input_buf_2, prf_output_buf, 32);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
              prf_input_buf_2, sizeof(prf_input_buf_2));
      element_from_hash(prf_result, prf_output_buf, 32);


#ifdef RANDOM_PERMUTE
      element_pow_zn(token->token_bit[permute[i]->index]->minus_one, g2r2k, prf_result);
#else
      element_pow_zn(token->token_bit[i]->minus_one, g2r2k, prf_result);
#endif

      // +1的部分等于是本来加一又加一, 就把输出转到mpz_t加二后模后计算,
      // 这里直接用prf_input_buf_2作为第二次输入因为prf_input_buf_2就是第一次的输出
      mpz_import(SHA_to_mpz, 32, 1, 1, -1, 0, prf_input_buf_2);
      mpz_add_ui(SHA_to_mpz, SHA_to_mpz, 2);
      mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
      mpz_export(prf_input_buf_2, NULL, 1, 1, -1, 0, SHA_to_mpz);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
              prf_input_buf_2, sizeof(prf_input_buf_2));
      element_from_hash(prf_result, prf_output_buf, 32);

#ifdef RANDOM_PERMUTE
      element_pow_zn(token->token_bit[permute[i]->index]->add_one, g2r2k, prf_result);
#else
      element_pow_zn(token->token_bit[i]->add_one, g2r2k, prf_result);
#endif
    } else {
      // 如果是0, 那就加一模算sha输出计算, 然后减一模算sha输出计算
      mpz_import(SHA_to_mpz, 32, 1, 1, -1, 0, prf_output_buf);
      mpz_add_ui(SHA_to_mpz, SHA_to_mpz, 1);
      mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
      mpz_export(prf_input_buf_2, NULL, 1, 1, -1, 0, SHA_to_mpz);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
              prf_input_buf_2, sizeof(prf_input_buf_2));
      element_from_hash(prf_result, prf_output_buf, 32);

#ifdef RANDOM_PERMUTE
      element_pow_zn(token->token_bit[permute[i]->index]->add_one , g2r2k, prf_result);
#else
      element_pow_zn(token->token_bit[i]->add_one , g2r2k, prf_result);
#endif

      // 刚才的值直接-2就是本来要减一的值
      mpz_sub_ui(SHA_to_mpz, SHA_to_mpz, 2);
      mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
      mpz_export(prf_input_buf_2, NULL, 1, 1, -1, 0, SHA_to_mpz);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
              prf_input_buf_2, sizeof(prf_input_buf_2));
      element_from_hash(prf_result, prf_output_buf, 32);

#ifdef RANDOM_PERMUTE
      element_pow_zn(token->token_bit[permute[i]->index]->minus_one , g2r2k, prf_result);
#else
      element_pow_zn(token->token_bit[i]->minus_one , g2r2k, prf_result);
#endif
    }
    
    // add the current bit of the message to the running prefix
    value[byteind] |= mask;

    // increment the index for the next iteration of the loop
    (*index)++;
  }
  
#ifdef RANDOM_PERMUTE
  free(permute);
#endif
  mpz_clear(SHA_to_mpz);
  mpz_clear(SHA_256_MAX);
  element_clear(g2r2k);
  element_clear(prf_result);

  return ERROR_NONE;
}

int ore_token_gen(ore_token token, uint64_t msg, pairing_t pairing, element_t k) {
  return _ore_token_gen(token, (byte *)&msg, sizeof(msg), pairing, k);
}

int ore_compare(int *result_p, ore_ciphertext ctxt, ore_token token, pairing_t pairing) {
  // 首先检查两个长度是否相等, 是否都初始化过了
  if ((ctxt->params->initialized != token->params->initialized) ||
      (ctxt->params->nbits != token->params->nbits)) {
    return ERROR_PARAMS_MISMATCH;
  }
  if(!ctxt->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }
  if (!token->initialized) {
    return ERROR_TOKEN_NOT_INITIALIZED;
  }

  int res = 0;

  element_t temp1, temp2, temp3;
  element_init_GT(temp1, pairing);
  element_init_GT(temp2, pairing);
  element_init_GT(temp3, pairing);

  uint32_t nbits = token->params->nbits;
#ifdef RANDOM_PERMUTE
  // Because the ciphertext and token have been randomly permuted,
  // this test function requires O(n^2) compare complexity, but
  // we only need 3n pairing because we can compute and store
  // pairing results for token before perform the real compare.

  // temporarily store pairing results for token.
  ore_token_bit token_result[nbits];
  for (uint32_t i = 0; i < nbits; i++) {
    element_init_GT(token_result[i]->add_one, pairing);
    element_init_GT(token_result[i]->minus_one, pairing);
    pairing_apply(token_result[i]->add_one, ctxt->g1r1, token->token_bit[i]->add_one, pairing);
    pairing_apply(token_result[i]->minus_one, ctxt->g1r1, token->token_bit[i]->minus_one, pairing);
  }

  bool break_flag = false;
  for (uint32_t i = 0; i < nbits; i++) {
    pairing_apply(temp1, ctxt->bit_ctxt[i], token->g2r2, pairing);
    for (uint32_t j = 0; j < nbits; j++) {
      // pairing_apply(temp2, ctxt->g1r1, token->token_bit[j]->add_one, pairing);
      // pairing_apply(temp3, ctxt->g1r1, token->token_bit[j]->minus_one, pairing);
      if (!element_cmp(temp1, token_result[j]->add_one)) {
        res = 1;
        break_flag = true;
        break;
      }
      if (!element_cmp(temp1, token_result[j]->minus_one)) {
        res = -1;
        break_flag = true;
        break;
      }
    }
    if (break_flag)
      break;
  }

  // clear pairing results for token.
  for (uint32_t i = 0; i < nbits; i++) {
    element_clear(token_result[i]->add_one);
    element_clear(token_result[i]->minus_one);
  }
#else
  // When using fixed permutation, we didn't permute the ciphertext and token
  // using the same permutation, instead, given this implementation is only a
  // proof of concept and benchmarking tool for our cryptographic primitives,
  // we implement the permutation here to achieve the same effect.
  rand_permute *permute = (rand_permute *)malloc(sizeof(rand_permute) * nbits);
  for (uint32_t i = 0; i < nbits; i++) {
    permute[i]->index = i;
    permute[i]->rando = rand();
  }
  qsort(permute, nbits, sizeof(permute), comp);
  for (uint32_t i = 0; i < nbits; i++) {
    pairing_apply(temp1, ctxt->bit_ctxt[permute[i]->index], token->g2r2, pairing);
    pairing_apply(temp2, ctxt->g1r1, token->token_bit[permute[i]->index]->add_one, pairing);
    pairing_apply(temp3, ctxt->g1r1, token->token_bit[permute[i]->index]->minus_one, pairing);
    if (!element_cmp(temp1, temp2)) {
      res = 1;
      // printf("第一个产生区别的比特位是：%u\n", i + 1);
      break;
    }
    if (!element_cmp(temp1, temp3)) {
      res = -1;
      // printf("第一个产生区别的比特位是：%u\n", i + 1);
      break;
    }
  }
  free(permute);
#endif

  *result_p = res;
  element_clear(temp1);
  element_clear(temp2);
  element_clear(temp3);
  return ERROR_NONE;
}

int clear_ore_ciphertext(ore_ciphertext ctxt) {
  if (ctxt == NULL) {
    return ERROR_NONE;
  }
  uint32_t nbits = ctxt->params->nbits;
  for (uint32_t i = 0; i < nbits; i++) {
    element_clear(ctxt->bit_ctxt[i]);
  }
  element_clear(ctxt->g1r1);

  return ERROR_NONE;
}

int clear_ore_token(ore_token token) {
  if (token == NULL) {
    return ERROR_NONE;
  }
  uint32_t nbits = token->params->nbits;
  for (uint32_t i = 0; i < nbits; i++) {
    element_clear(token->token_bit[i]->add_one);
    element_clear(token->token_bit[i]->minus_one);
  }
  element_clear(token->g2r2);

  return ERROR_NONE;
}

int clear_pairing(pairing_t pairing, element_t g1, element_t g2) {
  // Pairing must be the last one to be cleared.
  element_clear(g1);
  element_clear(g2);
  pairing_clear(pairing);

  return ERROR_NONE;
}