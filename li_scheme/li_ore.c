#include "./../crypto.h"
#include "./../errors.h"
#include "li_ore.h"

#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>


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
    element_init_G1(ctxt->ctxt_bit[i]->c11, pairing);
    element_init_G1(ctxt->ctxt_bit[i]->c12, pairing);
    element_init_G1(ctxt->ctxt_bit[i]->c21, pairing);
    element_init_G1(ctxt->ctxt_bit[i]->c22, pairing);
  }

  ctxt->initialized = true;
  return ERROR_NONE;
}

int init_ore_token(ore_token token, pairing_t pairing, element_t g2) {
  if (token == NULL) {
    return ERROR_NULL_POINTER;
  }

  element_init_G2(token->t1, pairing);
  element_init_G2(token->t2, pairing);

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
 * @param g1       generator of group G1
 * @param a        secert key a
 * @param x        secert key x
 *
 * @return ERROR_NONE on success
 */
static int _ore_encryption(ore_ciphertext ctxt, byte *buf, uint32_t buflen,\
                           pairing_t pairing, element_t g1, element_t a, element_t x) {
  if (!ctxt->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }

  uint32_t nbits = ctxt->params->nbits;

  uint32_t nbytes = (nbits + 7) / 8;
  
  byte prf_input_buf[sizeof(uint32_t) + nbytes];
  memset(prf_input_buf, 0, sizeof(prf_input_buf));


  byte msgbuf[nbytes];
  byte prf_output_buf[SHA256_OUTPUT_BYTES];

  // drop any extra bytes that have been provided
  if (buflen >= nbytes) {
    memcpy(msgbuf, buf, nbytes);
  }
  else {
    memcpy(msgbuf, buf, buflen);
  }

  element_t g1x;
  element_init_G1(g1x, pairing);
  element_pow_zn(g1x, g1, x);

  element_t r1, r2;
  element_init_Zr(r1, pairing);
  element_init_Zr(r2, pairing);

  element_t prf_result;
  element_init_G1(prf_result, pairing);


  uint32_t *index = (uint32_t *)prf_input_buf;

  byte *value = &prf_input_buf[sizeof(uint32_t)];

  uint32_t offset = (8 - (nbits % 8)) % 8;

  for (uint32_t i = 0; i < nbits; i++) {
    // get the current bit of the message
    uint32_t byteind = nbytes - 1 - (i + offset) / 8;

    byte mask = msgbuf[byteind] & (1 << ((7 - (i + offset)) % 8));
    
    element_random(r1);
    element_pow_zn(ctxt->ctxt_bit[i]->c12, g1, r1);
    element_random(r2);
    element_pow_zn(ctxt->ctxt_bit[i]->c22, g1, r2);

    if (mask > 0) {
      memset(&prf_input_buf[1], 1, 1);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
            prf_input_buf, sizeof(prf_input_buf));

      element_from_hash(prf_result, prf_output_buf, 32);
      element_pow_zn(ctxt->ctxt_bit[i]->c11, g1x, r1);
      element_mul(ctxt->ctxt_bit[i]->c11, prf_result, ctxt->ctxt_bit[i]->c11);
      element_pow_zn(ctxt->ctxt_bit[i]->c11, ctxt->ctxt_bit[i]->c11, a);
      
      memset(&prf_input_buf[1], 2, 1);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
            prf_input_buf, sizeof(prf_input_buf));
      element_from_hash(prf_result, prf_output_buf, 32);
      element_pow_zn(ctxt->ctxt_bit[i]->c21, g1x, r2);
      element_mul(ctxt->ctxt_bit[i]->c21, prf_result, ctxt->ctxt_bit[i]->c21);
      element_pow_zn(ctxt->ctxt_bit[i]->c21, ctxt->ctxt_bit[i]->c21, a);
    } else {
      memset(&prf_input_buf[1], 0, 1);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
            prf_input_buf, sizeof(prf_input_buf));
      element_from_hash(prf_result, prf_output_buf, 32);
      element_pow_zn(ctxt->ctxt_bit[i]->c11, g1x, r1);
      element_mul(ctxt->ctxt_bit[i]->c11, prf_result, ctxt->ctxt_bit[i]->c11);
      element_pow_zn(ctxt->ctxt_bit[i]->c11, ctxt->ctxt_bit[i]->c11, a);
      
      memset(&prf_input_buf[1], 1, 1);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
            prf_input_buf, sizeof(prf_input_buf));
      element_from_hash(prf_result, prf_output_buf, 32);
      element_pow_zn(ctxt->ctxt_bit[i]->c21, g1x, r2);
      element_mul(ctxt->ctxt_bit[i]->c21, prf_result, ctxt->ctxt_bit[i]->c21);
      element_pow_zn(ctxt->ctxt_bit[i]->c21, ctxt->ctxt_bit[i]->c21, a);
    }

    // add the current bit of the message to the running prefix
    value[byteind] |= mask;

    // increment the index for the next iteration of the loop
    (*index)++;
  }

  element_clear(g1x);
  element_clear(prf_result);
  element_clear(r1);
  element_clear(r2);
  return ERROR_NONE;
}

int ore_encryption(ore_ciphertext ctxt, uint64_t msg, pairing_t pairing, element_t g1,
                   element_t a, element_t x) {
  return _ore_encryption(ctxt, (byte *)&msg, sizeof(msg), pairing, g1, a, x);
}


int ore_token_gen(ore_token token, pairing_t pairing, element_t g2, element_t a, element_t x) {
  if (!token->initialized) {
    return ERROR_TOKEN_NOT_INITIALIZED;
  }
  element_t b, abx;
  element_init_Zr(b, pairing);
  element_init_Zr(abx, pairing);
  element_random(b);
  element_random(abx);

  element_pow_zn(token->t1, g2, b);
  element_mul(abx, a, b);
  element_mul(abx, abx, x);
  element_pow_zn(token->t2, g2, abx);

  element_clear(b);
  element_clear(abx);
  return ERROR_NONE;
}

int ore_compare(int *result_p, ore_ciphertext ctxt1, ore_ciphertext ctxt2, ore_token token, pairing_t pairing) {
  if ((ctxt1->params->initialized != ctxt2->params->initialized) ||
      (ctxt1->params->nbits != ctxt2->params->nbits)) {
    return ERROR_PARAMS_MISMATCH;
  }
  if(!ctxt1->initialized || !ctxt2->initialized) {
    return ERROR_CTXT_NOT_INITIALIZED;
  }
  if (!token->initialized) {
    return ERROR_TOKEN_NOT_INITIALIZED;
  }

  int res = 0;

  element_t temp1, temp2, temp3, temp4;
  element_init_GT(temp1, pairing);
  element_init_GT(temp2, pairing);
  element_init_GT(temp3, pairing);
  element_init_GT(temp4, pairing);

  uint32_t nbits = ctxt1->params->nbits;

  for (uint32_t i = 0; i < nbits; i++) {
    pairing_apply(temp1, ctxt1->ctxt_bit[i]->c11, token->t1, pairing);
    pairing_apply(temp2, ctxt1->ctxt_bit[i]->c12, token->t2, pairing);
    pairing_apply(temp3, ctxt2->ctxt_bit[i]->c21, token->t1, pairing);
    pairing_apply(temp4, ctxt2->ctxt_bit[i]->c22, token->t2, pairing);
    element_mul(temp1, temp1, temp4);
    element_mul(temp2, temp2, temp3);
    if (!element_cmp(temp1, temp2)) {
      res = 1;
      break;
    }

    pairing_apply(temp1, ctxt1->ctxt_bit[i]->c21, token->t1, pairing);
    pairing_apply(temp2, ctxt1->ctxt_bit[i]->c22, token->t2, pairing);
    pairing_apply(temp3, ctxt2->ctxt_bit[i]->c11, token->t1, pairing);
    pairing_apply(temp4, ctxt2->ctxt_bit[i]->c12, token->t2, pairing);
    element_mul(temp1, temp1, temp4);
    element_mul(temp2, temp2, temp3);
    if (!element_cmp(temp1, temp2)) {
      res = -1;
      break;
    }
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
    element_clear(ctxt->ctxt_bit[i]->c11);
    element_clear(ctxt->ctxt_bit[i]->c12);
    element_clear(ctxt->ctxt_bit[i]->c21);
    element_clear(ctxt->ctxt_bit[i]->c22);
  }
  return ERROR_NONE;
}

int clear_ore_token(ore_token token) {
  if (token == NULL) {
    return ERROR_NONE;
  }
  element_clear(token->t1);
  element_clear(token->t2);
  return ERROR_NONE;
}

int clear_pairing(pairing_t pairing, element_t g1, element_t g2) {
  // Pairing must be the last one to be cleared.
  element_clear(g1);
  element_clear(g2);
  pairing_clear(pairing);
  return ERROR_NONE;
}