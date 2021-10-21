# m-ORE
This is the implementation of the multi-client order-revealing encryption (m-ORE) schemes in the paper: [Efficient Multi-client Order-Revealing Encryption and Its Applications](https://link.springer.com/chapter/10.1007%2F978-3-030-88428-4_3).

If you have any questions, please contact me at: <cylv_1@stu.xidian.edu.cn>. 
## Prerequisites ##
Required environment
- [OpenSSL-1.1.1](https://www.openssl.org/source/)
- [GMP-6.2.0](https://gmplib.org/)
- [PBC-0.5.14](https://crypto.stanford.edu/pbc/download.html)
## Installation ##
``` shell
git clone git@github.com:collisionl/m-ORE.git
cd m-ORE
make
```
## Run the test ##
Run the correctness check by 
``` shell
# Requires type-d parameter of PBC library as input to generate asymmetric pairing
./tests/test_ore < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
``` 
Run the benchmark by
``` shell
./tests/time_ore < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
``` 

## Cash et al.'s scheme and Li et al.'s scheme ##
We also implemented the scheme of Cash et al. at /cash_scheme and the scheme of Li et al. at /li_scheme.

See the paper of Cash et al. at [ePrint](https://eprint.iacr.org/2018/698.pdf) and paper of Li et al. at [ACM](https://dl.acm.org/doi/abs/10.1145/3321705.3329829).

Run the correctness check by 
``` shell
cd cash_scheme (or li_scheme)
make
./tests/test_cash_ore (or ./tests/test_li_ore) < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
``` 
Run the benchmark by
``` shell
./tests/time_cash_ore (or ./tests/time_li_ore) < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
``` 
