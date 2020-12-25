#include "cash_ore.h"
#include "./../errors.h"


#include <stdint.h>
#include <stdio.h>

#define ERR_CHECK(x) if((err = x) != ERROR_NONE) { return err; }

/**
 * Generates a random 64-bit integers and encrypts it, then generates a
 * 64-bit integers and use it to generate a token
 * The encrypted integers are chosen randomly.
 *
 * @return 0 on success, -1 on failure, and an error if it occurred during the
 * encryption or comparison phase
 */
static int check_ore(pairing_t pairing, element_t g1, element_t g2, int err) {
    // test 32-bit ctxt, can modify up to 64
    uint32_t nbits = 32;

    uint64_t n1 = rand();
    uint64_t n2 = rand();


    int cmp = (n1 < n2) ? -1 : 1;
    if (n1 == n2) {
        cmp = 0;
    }

    ore_params params;
    ERR_CHECK(init_ore_params(params, nbits));

    element_t k;
    element_init_Zr(k, pairing);
    element_random(k);

    ore_ciphertext ctxt1;
    ERR_CHECK(init_ore_ciphertext(ctxt1, params, pairing));

    ore_ciphertext ctxt2;
    ERR_CHECK(init_ore_ciphertext(ctxt2, params, pairing));

    ERR_CHECK(ore_encryption(ctxt1, n1, pairing, k, g1, g2));
    ERR_CHECK(ore_encryption(ctxt2, n2, pairing, k, g1, g2));

    int ret = 0;
    int res;
    ERR_CHECK(ore_compare(&res, ctxt1, ctxt2, pairing));
    if (res == cmp) {
        ret = 0;  // success
    }
    else {
        ret = -1; // fail
    }

    ERR_CHECK(clear_ore_ciphertext(ctxt1));
    ERR_CHECK(clear_ore_ciphertext(ctxt2));

    element_clear(k);
    return ret;
}

int main(int argc, char **argv) {
    srand((unsigned)time(NULL));

    printf("Testing ORE\n");


    fflush(stdout);

    int err = 0;
    pairing_t pairing;
    element_t g1, g2;
    ERR_CHECK(init_pairing(pairing, g1, g2));

    int test_round = 10;
    for (int i = 0; i < test_round; i++) {
        printf("round %d\n", i + 1);

        if (check_ore(pairing, g1, g2, err) != ERROR_NONE) {
            printf("FAIL\n");
            return -1;
        }
    }

    printf("PASS\n");
    ERR_CHECK(clear_pairing(pairing, g1, g2));
    return 0;
}
