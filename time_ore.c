#include "ore.h"
#include "errors.h"

#include <stdio.h>
#include <time.h>

static int _err;
#define ERR_CHECK(x)            \
  if ((_err = x) != ERROR_NONE) \
  {                             \
    return _err;                \
  }

int main(int argc, char **argv) {
  const uint32_t NBITS[] = {8, 16, 24, 32, 48, 64};

  const int N_ENC_TRIALS = 100;
  const int N_TGEN_TRIALS = 100;
  const int N_CMP_TRIALS = 100;

  uint32_t nbits_len = sizeof(NBITS) / sizeof(int);

  printf("n = bit length of plaintext space\n\n");
  printf("%2s %12s %15s %15s %12s %16s %16s %18s %18s %16s\n",
         "n", "enc iter", "enc avg (ms)", "enc total (s)", "cmp iter", "cmp avg (ms)",\
          "cmp total (s)", "ctxt_len (bytes)", "token_len (bytes)", "token_gen (ms)");

  pairing_t pairing;
  element_t g1, g2;
  ERR_CHECK(init_pairing(pairing, g1, g2));
  element_t k;
  element_init_Zr(k, pairing);
  element_random(k);
  uint64_t byte_len_of_ctxt = 0;
  uint64_t byte_len_of_token = 0;

  for (int i = 0; i < nbits_len; i++) {
    ore_params params;
    ERR_CHECK(init_ore_params(params, NBITS[i]));

    ore_ciphertext ctxt;
    ERR_CHECK(init_ore_ciphertext(ctxt, params, pairing, g1));

    clock_t start_time = clock();
    int enc_trials = N_ENC_TRIALS / (i + 1);
    for (int j = 0; j < enc_trials; j++) {
      ERR_CHECK(ore_encryption(ctxt, rand(), pairing, k));
    }
    byte_len_of_ctxt = sizeof(bool) + sizeof(ore_params) + sizeof(element_t)*(NBITS[i] + 1);
    double enc_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    double enc_time = enc_time_elapsed / enc_trials * 1000;

    int res;

    ore_token token;
    ERR_CHECK(init_ore_token(token, params, pairing, g2));
    int token_gen_trials = N_TGEN_TRIALS / (i + 1);
    start_time = clock();
    for (int j = 0; j < token_gen_trials; j++) {
      ERR_CHECK(ore_token_gen(token, rand(), pairing, k));
    }
    double token_gen_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    double token_gen_time = token_gen_time_elapsed / token_gen_trials * 1000;
    byte_len_of_token = sizeof(bool) + sizeof(ore_params) + \
    sizeof(element_t) + sizeof(ore_token_bit)*(NBITS[i] + 1);
    

    start_time = clock();
    for (int j = 0; j < N_CMP_TRIALS; j++) {
      ore_compare(&res, ctxt, token, pairing);
    }
    double cmp_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    double cmp_time = cmp_time_elapsed / N_CMP_TRIALS * 1000;

    printf("%2d %12d %15.2f %15.2f %12d %16.2f %16.2f %18lu %18lu %16.2f\n",
           NBITS[i], enc_trials, enc_time, enc_time_elapsed, N_CMP_TRIALS, cmp_time,
           cmp_time_elapsed, byte_len_of_ctxt, byte_len_of_token, token_gen_time);

    ERR_CHECK(clear_ore_ciphertext(ctxt));
    ERR_CHECK(clear_ore_token(token));
  }

  element_clear(k);
  ERR_CHECK(clear_pairing(pairing, g1, g2));
  return 0;
}