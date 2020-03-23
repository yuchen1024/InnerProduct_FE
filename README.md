# DDH-based Simple Functional Encryption for Inner Product

## Overview

This is an implementation of DDH-based Simple Functional Encryption for Inner Product, 
mostly build upon ElGamal in the exponent.

## Specifications

- OS: MAC OS x64, Linux x64
- Language: C++
- Requires: OpenSSL


## Code Structure
- README.md


- /build: compile and execute 
  * CMakeLists.txt: cmake file
  * test_IPFE: the resulting executable file
  * point2index.table: the hashmap used for DLOG algorithm (if this file does not exist, the program will generate one)


- /global: global.hpp --- define global variables


- /depend: dependent files
  * routines.hpp: related routine algorithms, such as serialization functions 
  * print.hpp: print info for debug


- /src: source files
  * IPFE.hpp: implement DDH-based functional encryption for inner product, depending on calculate_dlog.hpp and routines.hpp
  * calculate_dlog.hpp: implement Shanks DLOG algorithm


- /test: test files
  * test_IPFE.cpp: main program - test IPFE, include correctness tests
  * test_IPFE: the resulting executable file
  * point2index.table: the hashmap used for DLOG algorithm (if this file does not exist, the program will generate one)


## Install OpenSSL (On Linux)
download [openssl-master.zip](https://github.com/openssl/openssl.git), then
```
  $ mkdir openssl
  $ mv openssl-master.zip /openssl
  $ unzip openssl-master.zip
  $ cd openssl-master
  $ ./config shared
  $ ./make
  $ ./make test
  $ ./make install
```

## Compile and Run

### method 1

```
  $ cd build
  $ cmake .
  $ make
  $ ./test_IPFE
```

### method 2

```
  $ cd test
  $ ./make_test_IPFE.sh
  $ ./test_IPFE
```

## Parameter choices

- elliptic curve choice
  * The default elliptic curve is "NID_X9_62_prime256v1". 
    You can choose your favorite EC curve by specifying the curve_id

- message space choice
  * The default message space is [0, 2^10). 
    You can modify the message space by changing the variable <font color=red>MSG_LEN</font> in public parameter. 

- dimension choice
  * The default dimension is [0, 2^10). 
    You can modify the message space by changing the variable <font color=red>DIMENSION_LEN</font> in public parameter. 

- dlog space choice
  * The default message space is [0, 2^32). 
    You can modify the message space by changing the variable <font color=red>DLOG_LEN</font> in public parameter. 


- preprocessing choice
  * The default size of hashmap used for Shanks DLOG algorithm is roughly 264MB. 
    One could change its size by changing the variable <font color=red>MAP_TUNNING</font> in public parameters. 


- thread choice
  * The default thread number for parallel decryption is 4. You can adjust it to match the number of cores 
    of your CPU. One could change its by changing the variable <font color=red>DEC_THREAD_NUM</font> in public parameters. 

## APIs of Twisted ElGamal (single thread)
  * <font color=blue>global_initialize(int curve_id)</font>: initialize the OpenSSL environment
  * <font color=blue>global_finalize()</font>: finalize the OpenSSL environment
  * <font color=blue>Twisted_ElGamal_Setup(pp, MSG_LEN, MAP_TUNNING, DEC_THREAD_NUM)</font>: generate system-wide public parameters of twisted ElGamal
  * <font color=blue>Twisted_ElGamal_Initialize(pp)</font>: generate hash map for fast decryption
  * <font color=blue>Twisted_ElGamal_KeyGen(pp, keypair)</font>: generate a keypair
  * <font color=blue>Twisted_ElGamal_Enc(pp, pk, m, CT)</font>: encrypt message 
  * <font color=blue>Twisted_ElGamal_Dec(pp, sk, CT, m)</font>: decrypt ciphertext
  * <font color=blue>Twisted_ElGamal_ReRand(pp, pk, sk, CT, CT_new, r)</font>: re-randomize ciphertext with given randomness
  * <font color=blue>Twisted_ElGamal_HomoAdd(CT_result, CT1, CT2)</font>: homomorphic addition
  * <font color=blue>Twisted_ElGamal_HomoSub(CT_result, CT1, CT2)</font>: homomorphic subtraction
  * <font color=blue>Twisted_ElGamal_ScalarMul(CT_result, CT, k)</font>: scalar multiplication

We also provide parallel implementations, whose Enc, Dec, Scalar performances are better than those in single thread. 

## Tests 

- <font color=blue>test_twisted_elgamal()</font>: basic correctness test
  * random encryption and decryption test  
  * boundary encryption and decryption tests


- <font color=blue>benchmark_twisted_elgamal()</font>: collect the benchmark in single thread
  * setup
  * key generation
  * encryption
  * re-randomization
  * decryption
  * homomorphic addition
  * homomorphic subtract
  * scalar multiplication     


- <font color=blue>benchmark_parallel_twisted_elgamal()</font>: collect the benchmark in 2 thread
  * setup
  * key generation
  * encryption
  * re-randomization
  * decryption (4 thread)
  * homomorphic addition
  * homomorphic subtract
  * scalar multiplication 

## License

This library is licensed under the [MIT License](LICENSE).

