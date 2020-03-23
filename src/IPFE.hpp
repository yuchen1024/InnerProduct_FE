/************************************************************************************** 
this hpp initialize and finalize the global environment 
***************************************************************************************
* @author     DDH-based Functional Encryption for Inner Product, developed by Yu Chen
* @paper      PKC 2015 Simple Functional Encryption Schemes for Inner Products
* @copyright  MIT license (see LICENSE file)
***************************************************************************************/

#include "../global/global.hpp"
#include "../depends/print.hpp"
#include "../depends/routines.hpp"

#include "calculate_dlog.hpp"

const string hashmap_file  = "g_point2index.table"; // name of hashmap file

typedef vector<EC_POINT *> IPFE_MPK; 
typedef vector<BIGNUM *> IPFE_MSK;
typedef vector<BIGNUM *> IPFE_MSG;
typedef vector<BIGNUM *> IPFE_POLICY;

// define the structure of PP
struct IPFE_PP
{
    size_t MSG_LEN;        // the log size of message space
    BIGNUM *BN_MSG_SIZE;   // the size of message space
    
    size_t DIMENSION_LEN;  // the log size of dimension
    size_t DIMENSION;      // the dimension size

    size_t DLOG_LEN;       // the maximum dlog size that Shanks's algorithm can solve quickly
    BIGNUM *BN_DLOG_SIZE;  // the size of message space
    size_t TUNNING;        // increase this parameter in [0, RANGE_LEN/2]: larger table leads to less running time
    size_t THREAD_NUM;     // optimized number of threads for faster decryption: CPU dependent

    EC_POINT *g;           // the generator
};

// define the structure of fsk
struct IPFE_FSK
{
    vector<BIGNUM *> policy;  // policy of sk
    BIGNUM * sk;  // sk = <policy, msk>
};


// define the structure of ciphertext
struct IPFE_CT
{
    EC_POINT *X; // X = g^r 
    vector<EC_POINT *> Y; // Y_i = pk_i^{r} g^{m_i} 
};


/* allocate memory for PP */ 
void IPFE_PP_new(IPFE_PP &pp)
{ 
    pp.g = EC_POINT_new(group); 
    pp.BN_MSG_SIZE = BN_new(); 
    pp.BN_DLOG_SIZE = BN_new(); 
}

/* free memory of PP */ 
void IPFE_PP_free(IPFE_PP &pp)
{ 
    EC_POINT_free(pp.g);
    BN_free(pp.BN_MSG_SIZE); 
    BN_free(pp.BN_DLOG_SIZE); 
}

void IPFE_FSK_free(IPFE_FSK &fsk)
{
    BN_vec_free(fsk.policy); 
    BN_free(fsk.sk);  
}

void IPFE_CT_new(IPFE_PP &pp, IPFE_CT &CT)
{
    CT.X = EC_POINT_new(group);
    CT.Y.resize(pp.DIMENSION);  
    ECP_vec_new(CT.Y);
}

void IPFE_CT_free(IPFE_CT &CT)
{
    EC_POINT_free(CT.X); 
    ECP_vec_free(CT.Y);
}


void IPFE_PP_print(IPFE_PP &pp)
{
    cout << "the length of message space = " << pp.MSG_LEN << endl; 
    cout << "the dimension = " << pp.DIMENSION << endl; 
    cout << "the tunning parameter for fast decryption = " << pp.TUNNING << endl;
    ECP_print(pp.g, "pp.g"); 
} 

void IPFE_KP_print(IPFE_MPK &mpk, IPFE_MSK &msk)
{
    ECP_vec_print(mpk, "mpk"); 
    BN_vec_print(msk, "msk"); 
} 

void IPFE_CT_print(IPFE_CT &CT)
{
    ECP_print(CT.X, "CT.X");
    ECP_vec_print(CT.Y, "CT.Y");
} 


void IPFE_CT_serialize(IPFE_CT &CT, ofstream &fout)
{
    ECP_serialize(CT.X, fout); 
    ECP_vec_serialize(CT.Y, fout); 
} 

void IPFE_CT_deserialize(IPFE_CT &CT, ifstream &fin)
{
    ECP_deserialize(CT.X, fin); 
    ECP_vec_deserialize(CT.Y, fin); 
} 


/* Setup algorithm */ 
void IPFE_Setup(IPFE_PP &pp, size_t MSG_LEN, size_t DIMENSION_LEN, size_t DLOG_LEN, size_t TUNNING, size_t THREAD_NUM)
{ 
    pp.MSG_LEN = MSG_LEN;
    pp.DIMENSION_LEN = DIMENSION_LEN;
    pp.DLOG_LEN = DLOG_LEN; 
    if((DIMENSION_LEN+2*MSG_LEN) > DLOG_LEN){
        cout << "message space or dimension too large" << endl;  
        exit(EXIT_FAILURE);
    } 
    pp.TUNNING = TUNNING; 
    pp.THREAD_NUM = THREAD_NUM; 


    pp.DIMENSION = size_t(pow(2, pp.DIMENSION_LEN)); 

    /* set the message space to 2^{MSG_LEN} */
    BN_set_word(pp.BN_MSG_SIZE, uint64_t(pow(2, pp.MSG_LEN))); 

    /* set the result space to 2^{DLOG_LEN} */
    BN_set_word(pp.BN_DLOG_SIZE, uint64_t(pow(2, pp.DLOG_LEN))); 

    #ifdef DEBUG
    cout << "result space = [0, ";   
    cout << BN_bn2hex(pp.BN_DLOG_SIZE) << ')' << endl; 
    #endif
  
    EC_POINT_copy(pp.g, generator); 

    #ifdef DEBUG
    cout << "generate the public parameters for IPFE >>>" << endl; 
    IPFE_PP_print(pp); 
    #endif

    #ifdef DEMO
    cout << "Setup IPFE: generate public paraneters >>> " << endl; 
    #endif
}

/* initialize the hashmap to accelerate decryption */
void IPFE_Initialize(IPFE_PP &pp)
{
    #ifdef DEMO
    cout << "Initialize IPFE: generate hash table for fast decryption >>>" << endl; 
    #endif

    /* generate or load the point2index.table */
    if(!FILE_exist(hashmap_file))
    {
        // generate and serialize the point_2_index table
        HASHMAP_serialize(pp.g, hashmap_file, pp.DLOG_LEN, pp.TUNNING); 
    }
    HASHMAP_load(hashmap_file, pp.DLOG_LEN, pp.TUNNING);            // load the table from file 
}

/* KeyGen algorithm */ 
void IPFE_KeyGen(IPFE_PP &pp, IPFE_MPK &mpk, IPFE_MSK &msk)
{ 
    size_t l = size_t(pow(2, pp.DIMENSION_LEN)); 
    mpk.resize(l); msk.resize(l); 
    ECP_vec_new(mpk);
    BN_vec_new(msk); 
    
    BN_vec_random(msk); // msk[i] \sample Z_p

    for(auto i = 0; i < mpk.size(); i++){
        EC_POINT_mul(group, mpk[i], msk[i], NULL, NULL, bn_ctx); // mpk[i] = g^msk[i]  
    }
    #ifdef DEBUG
    cout << "key generation finished >>>" << endl;  
    IPFE_KP_print(mpk, msk); 
    #endif

    #ifdef DEMO
    cout << "IPFE KeyGen: generate (mpk, msk) >>>" << endl;  
    #endif
}

/* Key Derivation algorithm: compute fsk = Derive(msk, policy) */ 
void IPFE_FSK_Derive(IPFE_MSK &msk, IPFE_POLICY &policy, IPFE_FSK &fsk)
{
    size_t l = policy.size(); 
    fsk.policy.resize(l);    
    BN_vec_new(fsk.policy); 
    BN_vec_copy(fsk.policy, policy); 
    
    fsk.sk = BN_new();  
    BN_vec_inner_product(fsk.sk, msk, policy); // sk_y = <msk, y> 

    #ifdef DEMO
    cout << "IPFE KeyDerive: derive fsk from msk >>>" << endl;  
    #endif
}

/* Encryption algorithm: compute CT = Enc(mpk, m; r) */ 
void IPFE_Enc(IPFE_PP &pp, IPFE_MPK &mpk, IPFE_MSG &m, IPFE_CT &CT)
{ 
    // generate the random coins 
    BIGNUM *r = BN_new(); 
    BN_random(r);

    // begin encryption
    EC_POINT_mul(group, CT.X, r, NULL, NULL, bn_ctx); // X = g^r
    for(auto i = 0; i < CT.Y.size(); i++){
        EC_POINT_mul(group, CT.Y[i], m[i], mpk[i], r, bn_ctx);  // Y = pk^r g^m
    }
    BN_free(r); 

    #ifdef DEBUG
        cout << "IPFE encryption finishes >>>"<< endl;
        IPFE_CT_print(CT); 
    #endif

    #ifdef DEMO
    cout << "IPFE Enc: IPFE encryption finishes >>>" << endl;  
    #endif
}

/* Decryption algorithm: compute m = Dec(sk, CT) */ 
void IPFE_Dec(IPFE_PP &pp, IPFE_FSK &fsk, IPFE_CT &CT, BIGNUM * &result)
{ 
    //begin decryption  

    EC_POINT *M = EC_POINT_new(group); 
    ECP_vec_mul(M, CT.Y, fsk.policy); // \sum CT[i]^{y[i]}

    EC_POINT_mul(group, CT.X, NULL, CT.X, fsk.sk, bn_ctx); // CT_0^{sk_y} 
    EC_POINT_sub(M, M, CT.X);          

    // use parallel Shanks's algorithm to decrypt
    bool success = Parallel_Shanks_DLOG(result, pp.g, M, pp.DLOG_LEN, pp.TUNNING, pp.THREAD_NUM); 
    
    EC_POINT_free(M);
    if(success == false)
    {
        cout << "decyption fails in the specified range"; 
        exit(EXIT_FAILURE); 
    } 
    
    #ifdef DEMO
    cout << "IPFE Dec: IPFE decryption finishes >>>" << endl;  
    #endif 
}








