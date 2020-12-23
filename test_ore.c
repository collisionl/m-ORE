#include "ore.h"
#include "errors.h"
#include "flags.h"

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
    // 这里nbit表示明文长度
    uint32_t nbits = 64;

    // 随机生成明文, 写模数是为了正确判断两个数的大小
    // 如果nbits大于31之后, 再模之后变成了0, 如果把1改成longlong类型再对其作31以上的移位就正常了
    uint64_t n1 = rand() ;//% (((uint64_t) 1) << nbits);   //0x0314620303146203;//% (1LL << nbits);
    uint64_t n2 = rand() ;//% (((uint64_t) 1) << nbits);   //0x0314695103146203;//% (1LL << nbits);
    // OUTPUT输出随机产生的n1和n2
    // printf("n1:0x%016lx\n", n1);
    // printf("n2:0x%016lx\n", n2);
    // OUTPUT

    // 0是相等, -1是n1 < n2, 1是n1 > n2
    int cmp = (n1 < n2) ? -1 : 1;
    if (n1 == n2) {
        cmp = 0;
    }

    // 初始化密文的各种参数
    ore_params params;
    ERR_CHECK(init_ore_params(params, nbits));

    element_t k;
    element_init_Zr(k, pairing);
    element_random(k);

    
    // 初始化密文
    ore_ciphertext ctxt;
    ERR_CHECK(init_ore_ciphertext(ctxt, params, pairing, g1));

    // 初始化token
    ore_token token;
    ERR_CHECK(init_ore_token(token, params, pairing, g2));

    // 加密
    ERR_CHECK(ore_encryption(ctxt, n1, pairing, k));
 
    // 产生token
    ERR_CHECK(ore_token_gen(token, n2, pairing, k));


    // 比较, 使用&取地址, 传入后使用指针修改res
    int ret = 0;
    int res;
    ERR_CHECK(ore_compare(&res, ctxt, token, pairing));
    if (res == cmp) {
        ret = 0;  // success
    }
    else {
        ret = -1; // fail
    }

    // 清除内存
    ERR_CHECK(clear_ore_ciphertext(ctxt));
    ERR_CHECK(clear_ore_token(token));

    // 清除key
    element_clear(k);
    return ret;
}

int main(int argc, char **argv) {
    srand((unsigned)time(NULL));

#ifdef RANDOM_PERMUTE
    printf("Testing ORE with random permutation\n");
#else
    printf("Testing ORE with fixed permutation\n");
#endif

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