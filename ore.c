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
 * Function which performs the encryption of an input, storing the result
 * in a ciphertext.
 *
 * @param ctxt    The ciphertext to store the encryption
 * @param buf     The input in a byte array, encoded in little-endian
 * @param buflen  The length of the byte array input
 * @param pairing pairing
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

  // byte length of ctxt
  uint32_t nbytes = (nbits + 7) / 8;
  
  // initial the input buffer for prf 
  byte prf_input_buf[sizeof(uint32_t) + nbytes];
  memset(prf_input_buf, 0, sizeof(prf_input_buf));

  // message buffer
  byte msgbuf[nbytes];

  // initial the output buffer for prf
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

  // Precompute
  element_t g1r1k;
  element_init_G1(g1r1k, pairing);
  element_pow_zn(g1r1k, ctxt->g1r1, k);


  element_t prf_result;
  element_init_Zr(prf_result, pairing);


  // index is the same as prf_input_buf[0]
  uint32_t *index = (uint32_t *)prf_input_buf;


  byte *value = &prf_input_buf[sizeof(uint32_t)];

  uint32_t offset = (8 - (nbits % 8)) % 8;

  // Generate a random array
  rand_permute *permute = (rand_permute *)malloc(sizeof(rand_permute) * nbits);
  for (uint32_t i = 0; i < nbits; i++) {
    permute[i]->index = i;
    permute[i]->rando = rand();
  }
  qsort(permute, nbits, sizeof(permute), comp);

  for (uint32_t i = 0; i < nbits; i++) {
    // get the current bit of the message
    // little-endian
    uint32_t byteind = nbytes - 1 - (i + offset) / 8;

    // mask indicates whether this bit is 1 or 0
    byte mask = msgbuf[byteind] & (1 << ((7 - (i + offset)) % 8));

    sha_256(prf_output_buf, sizeof(prf_output_buf),
            prf_input_buf, sizeof(prf_input_buf));

    // first output as the second inout
    memcpy(prf_input_buf_2, prf_output_buf, 32);

    // If this bit is 1, it will be converted to mpz_t and then added 1 and modulo 2^256-1
    // and then converted to byte type as the second input
    if (mask > 0) {
      mpz_import(SHA_to_mpz, 32, 1, 1, -1, 0, prf_output_buf);
      mpz_add_ui(SHA_to_mpz, SHA_to_mpz, 1);
      mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
      mpz_export(prf_input_buf_2, NULL, 1, 1, -1, 0, SHA_to_mpz);
    }

    // Compute the second hash and use the result to generate elements in Zr 
    // to be used in the subsequent modular exponential operation, covering the result of the first prf operation
    sha_256(prf_output_buf, sizeof(prf_output_buf),
            prf_input_buf_2, sizeof(prf_input_buf_2));

    // hash to Zr
    element_from_hash(prf_result, prf_output_buf, 32);
    element_pow_zn(ctxt->bit_ctxt[permute[i]->index], g1r1k, prf_result);

    // add the current bit of the message to the running prefix
    value[byteind] |= mask;

    // increment the index for the next iteration of the loop
    (*index)++;
  }

  free(permute);
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

  uint32_t nbytes = (nbits + 7) / 8;

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

  // precompute
  element_t g2r2k;
  element_init_G2(g2r2k, pairing);
  element_pow_zn(g2r2k, token->g2r2, k);

  element_t prf_result;
  element_init_Zr(prf_result, pairing);

  uint32_t *index = (uint32_t *)prf_input_buf;

  byte *value = &prf_input_buf[sizeof(uint32_t)];

  uint32_t offset = (8 - (nbits % 8)) % 8;

  rand_permute *permute = (rand_permute *)malloc(sizeof(rand_permute) * nbits);
  for (uint32_t i = 0; i < nbits; i++) {
    permute[i]->index = i;
    permute[i]->rando = rand();
  }
  qsort(permute, nbits, sizeof(permute), comp);

  for (uint32_t i = 0; i < nbits; i++) {
    // get the current bit of the message
    uint32_t byteind = nbytes - 1 - (i + offset) / 8;

    byte mask = msgbuf[byteind] & (1 << ((7 - (i + offset)) % 8));

    sha_256(prf_output_buf, sizeof(prf_output_buf),
            prf_input_buf, sizeof(prf_input_buf));

    if (mask > 0) {
      memcpy(prf_input_buf_2, prf_output_buf, 32);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
              prf_input_buf_2, sizeof(prf_input_buf_2));
      element_from_hash(prf_result, prf_output_buf, 32);

      element_pow_zn(token->token_bit[permute[i]->index]->minus_one, g2r2k, prf_result);

      mpz_import(SHA_to_mpz, 32, 1, 1, -1, 0, prf_input_buf_2);
      mpz_add_ui(SHA_to_mpz, SHA_to_mpz, 2);
      mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
      mpz_export(prf_input_buf_2, NULL, 1, 1, -1, 0, SHA_to_mpz);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
              prf_input_buf_2, sizeof(prf_input_buf_2));
      element_from_hash(prf_result, prf_output_buf, 32);
      element_pow_zn(token->token_bit[permute[i]->index]->add_one, g2r2k, prf_result);
    } else {
      mpz_import(SHA_to_mpz, 32, 1, 1, -1, 0, prf_output_buf);
      mpz_add_ui(SHA_to_mpz, SHA_to_mpz, 1);
      mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
      mpz_export(prf_input_buf_2, NULL, 1, 1, -1, 0, SHA_to_mpz);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
              prf_input_buf_2, sizeof(prf_input_buf_2));
      element_from_hash(prf_result, prf_output_buf, 32);

      element_pow_zn(token->token_bit[permute[i]->index]->add_one , g2r2k, prf_result);

      mpz_sub_ui(SHA_to_mpz, SHA_to_mpz, 2);
      mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
      mpz_export(prf_input_buf_2, NULL, 1, 1, -1, 0, SHA_to_mpz);
      sha_256(prf_output_buf, sizeof(prf_output_buf),
              prf_input_buf_2, sizeof(prf_input_buf_2));
      element_from_hash(prf_result, prf_output_buf, 32);

      element_pow_zn(token->token_bit[permute[i]->index]->minus_one , g2r2k, prf_result);
    }
    
    // add the current bit of the message to the running prefix
    value[byteind] |= mask;

    // increment the index for the next iteration of the loop
    (*index)++;
  }
  
  free(permute);
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

  // Because the ciphertext and token have been randomly permuted,
  // this test function requires O(n^2) compare complexity, but
  // it only need 3n pairing because we can compute and store
  // pairing results for token before perform the real compare.

  // preprocessing
  pairing_pp_t pp;
  pairing_pp_init(pp, ctxt->g1r1, pairing);
  // temporarily store pairing results for token and ctxt.
  ore_token_bit token_result[nbits];
  for (uint32_t i = 0; i < nbits; i++) {
    element_init_GT(token_result[i]->add_one, pairing);
    element_init_GT(token_result[i]->minus_one, pairing);
    pairing_pp_apply(token_result[i]->add_one, token->token_bit[i]->add_one, pp);
    pairing_pp_apply(token_result[i]->minus_one, token->token_bit[i]->minus_one, pp);
  }
  pairing_pp_clear(pp);

  bool break_flag = false;
  for (uint32_t i = 0; i < nbits; i++) {
    pairing_apply(temp1, ctxt->bit_ctxt[i], token->g2r2, pairing);
    for (uint32_t j = 0; j < nbits; j++) {
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