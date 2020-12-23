#include "cash_ore.h"
#include "./../errors.h"

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
  const int N_CMP_TRIALS = 100;

  uint32_t nbits_len = sizeof(NBITS) / sizeof(int);

  printf("n = bit length of plaintext space\n\n");
  printf("%2s %12s %15s %15s %12s %15s %15s %15s\n",
         "n", "enc iter", "enc avg (ms)", "enc total (s)", "cmp iter", "cmp avg (ms)", "cmp total (s)", "len (bytes)");

  pairing_t pairing;
  element_t g1, g2;
  ERR_CHECK(init_pairing(pairing, g1, g2));
  element_t k;
  element_init_Zr(k, pairing);
  element_random(k);
  uint64_t byte_len_of_ctxt = 0;

  for (int i = 0; i < nbits_len; i++) {
    ore_params params;
    ERR_CHECK(init_ore_params(params, NBITS[i]));

    ore_ciphertext ctxt;
    ERR_CHECK(init_ore_ciphertext(ctxt, params, pairing));

    clock_t start_time = clock();
    int enc_trials = N_ENC_TRIALS / (i + 1);
    for (int j = 0; j < enc_trials; j++) {
      ERR_CHECK(ore_encryption(ctxt, rand(), pairing, k, g1, g2));
    }
    byte_len_of_ctxt = sizeof(ctxt);
    double enc_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    double enc_time = enc_time_elapsed / enc_trials * 1000;

    int res;

    ore_ciphertext ctxt2;
    ERR_CHECK(init_ore_ciphertext(ctxt2, params, pairing));
    ERR_CHECK(ore_encryption(ctxt2, rand(), pairing, k, g1, g2));

    start_time = clock();
    for (int j = 0; j < N_CMP_TRIALS; j++) {
      ore_compare(&res, ctxt, ctxt2, pairing);
    }
    double cmp_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    double cmp_time = cmp_time_elapsed / N_CMP_TRIALS * 1000;

    printf("%2d %12d %15.2f %15.2f %12d %15.2f %15.2f %15lu\n",
           NBITS[i], enc_trials, enc_time, enc_time_elapsed,
           N_CMP_TRIALS, cmp_time, cmp_time_elapsed, byte_len_of_ctxt);

    ERR_CHECK(clear_ore_ciphertext(ctxt));
    ERR_CHECK(clear_ore_ciphertext(ctxt2));
  }

  element_clear(k);
  ERR_CHECK(clear_pairing(pairing, g1, g2));
  return 0;
}
