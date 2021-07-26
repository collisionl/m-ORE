#include "li_ore.h"
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
    uint32_t nbits = 32;

    uint64_t n1 = rand() % (1 << nbits);
    uint64_t n2 = rand() % (1 << nbits);


    int cmp = (n1 < n2) ? -1 : 1;
    if (n1 == n2) {
        cmp = 0;
    }

    ore_params params;
    ERR_CHECK(init_ore_params(params, nbits));

    element_t a,x;
    element_init_Zr(a, pairing);
    element_init_Zr(x, pairing);
    element_random(a);
    element_random(x);

    ore_ciphertext ctxt1;
    ERR_CHECK(init_ore_ciphertext(ctxt1, params, pairing, g1));
    ore_ciphertext ctxt2;
    ERR_CHECK(init_ore_ciphertext(ctxt2, params, pairing, g1));

    ore_token token;
    ERR_CHECK(init_ore_token(token, pairing, g2));

    ERR_CHECK(ore_encryption(ctxt1, n1, pairing, g1, a, x));
    ERR_CHECK(ore_encryption(ctxt2, n2, pairing, g1, a, x));
    
    ERR_CHECK(ore_token_gen(token, pairing, g2, a, x));


    int ret = 0;
    int res;
    ERR_CHECK(ore_compare(&res, ctxt1, ctxt2, token, pairing));
    if (res == cmp) {
        ret = 0;  // success
    }
    else {
        ret = -1; // fail
    }

    ERR_CHECK(clear_ore_ciphertext(ctxt1));
    ERR_CHECK(clear_ore_ciphertext(ctxt2));
    ERR_CHECK(clear_ore_token(token));

    element_clear(a);
    element_clear(x);
    return ret;
}

int main(int argc, char **argv) {
    srand((unsigned)time(NULL));

    printf("Testing ORE...\n");

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
