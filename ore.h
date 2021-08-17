#ifndef __ORE_H__
#define __ORE_H__

#include "crypto.h"
#include "errors.h"

#include <pbc/pbc.h>
#include <stdbool.h>

static const int PLAINTEXT_BIT = 64;

typedef struct {
  bool initialized; // whether or not these parameters have been initialized
  uint32_t nbits;   // the number of bits in the plaintext elements
} ore_params[1];

typedef struct {
  bool initialized;
  ore_params params;
  element_t bit_ctxt[PLAINTEXT_BIT];
  element_t g1r1k21;
} ore_ciphertext[1];

typedef struct {
  element_t add_one;
  element_t minus_one;
} ore_token_bit[1];

typedef struct {
  bool initialized;
  ore_params params;
  ore_token_bit token_bit[PLAINTEXT_BIT];
  element_t g2r2k22;
} ore_token[1];

/**
 * Initializes an ore_params type by setting its parameters, number of bits.
 * @param params      The params to initialize
 * @param nbits       The number of bits of an input to the encryption scheme
 *
 * @return ERROR_NONE on success, ERROR_PARAMS_INVALID if the parameter settings
 *         are invalid.
 */
int init_ore_params(ore_params params, uint32_t nbits);

/**
 * initialize a pairing and generators of group G1 and G2
 * 
 * @param pairing      pairing
 * @param g1           generator of group G1
 * @param g2           generator of group G2
 *
 * @return ERROR_NONE on success, ERROR_PAIRING_NOT_INITIALIZED when
 * pairing is not initialized, ERROR_PAIRING_IS_SYMMETRIC when two
 * group is symmetric.(Our scheme requires two groups to be asymmetric.)
 */
int init_pairing(pairing_t pairing, element_t g1, element_t g2);

/**
 * Initializes a ciphertext with the parameters described by params.
 *
 * @param ctxt     The ciphertext to initialize
 * @param params   The parameters to initialize the ciphertext with
 * @param pairing  pairing
 * @param g1       generator of group G1
 * @param k21      hash key k21
 * 
 * @return ERROR_NONE on success, ERROR_CTXT_NOT_INITIALIZED when
 * ctxt is not initialized.
 */
int init_ore_ciphertext(ore_ciphertext ctxt, ore_params params,
                        pairing_t pairing, element_t g1, element_t k21);

/**
 * Initializes a token with the parameters described by params.
 *
 * @param token    The token to initialize
 * @param params   The parameters to initialize the ciphertext with
 * @param pairing  pairing
 * @param g2       generator of group G2
 * @param k22      hash key k22
 *
 * @return ERROR_NONE on success, ERROR_TOKEN_NOT_INITIALIZED when
 * token is not initialized.
 */
int init_ore_token(ore_token token, ore_params params,
                   pairing_t pairing, element_t g2, element_t k22);

/**
 * Function to receive plaintext msg.
 *
 * The ciphertext must also be initialized (by a call to init_ore_ciphertext)
 * before calling this function.
 *
 * @param ctxt     The ciphertext to store the encrypt result.
 * @param msg      The input in uint64_t format.
 * @param pairing  pairing
 * @param k1       prf key k1
 * 
 * @return ERROR_NONE on success
 */
int ore_encryption(ore_ciphertext ctxt, uint64_t msg, pairing_t pairing,
                   element_t k1);

/**
 * Function to receive plaintext msg.
 *
 * Token must also be initialized before calling this function.
 *
 * @param token    The token
 * @param msg      The input in a uint64_t
 * @param pairing  pairing
 * @param k1       prf key k1
 * 
 * @return ERROR_NONE on success
 */
int ore_token_gen(ore_token token, uint64_t msg, pairing_t pairing, element_t k1);

/**
 * Performs the comparison of a ciphertexts and a token to determine the ordering 
 * of their underlying plaintexts.
 * 
 * The ciphertexts and the token must have been initialized
 * before calling this function.
 *
 * @param result_p A pointer containing the result of the comparison, which is 1
 *                 if ctxt is greater than token, -1 if ctxt is less than token,
 *                 and 0 if they encrypt equal plaintexts.
 * @param ctxt     The ciphertext
 * @param token    The token
 * @param pairing  pairing
 *
 * @return ERROR_NONE on success
 */
int ore_compare(int *result_p, ore_ciphertext ctxt, ore_token token, pairing_t pairing);

/**
 * Clears a ciphertext
 *
 * @param ctxt   The ciphertext to clear
 *
 * @return ERROR_NONE on success
 */
int clear_ore_ciphertext(ore_ciphertext ctxt);

/**
 * Clears a token
 *
 * @param token   The token to clear
 *
 * @return ERROR_NONE on success
 */
int clear_ore_token(ore_token token);

/**
 * Clears a pairing params including g1 and g2.
 *
 * @param pairing  pairing
 * @param g1       generator of group G1
 * @param g2       generator of group G2
 * 
 * @return ERROR_NONE on success
 */
int clear_pairing(pairing_t pairing, element_t g1, element_t g2);

#endif /* __ORE_H__ */