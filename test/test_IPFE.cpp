#define DEMO
//#define DEBUG

#include "../src/IPFE.hpp"

void test_IPFE(size_t MSG_LEN, size_t DIMENTION_LEN, size_t DLOG_LEN, size_t MAP_TUNNING, size_t DEC_THREAD_NUM)
{
    cout << "begin the basic correctness test >>>" << endl; 
    
    IPFE_PP pp; 
    IPFE_PP_new(pp);  

    IPFE_Setup(pp, MSG_LEN, DIMENTION_LEN, DLOG_LEN, MAP_TUNNING, DEC_THREAD_NUM);
    IPFE_Initialize(pp); 

    IPFE_MPK mpk;
    IPFE_MSK msk;  
    IPFE_KeyGen(pp, mpk, msk); 

    IPFE_CT CT; 
    IPFE_CT_new(pp, CT);

    IPFE_MSG m; 
    m.resize(pp.DIMENSION);
    BN_vec_new(m);  

    IPFE_POLICY policy;
    policy.resize(pp.DIMENSION); 
    BN_vec_new(policy);  
 
    BIGNUM * result = BN_new();
    BIGNUM * result_prime = BN_new();

    /* random test */ 
    SplitLine_print('-'); 
    cout << "begin the random test >>>" << endl; 

    #ifdef DEMO
    cout << "Generate random message vector >>>" << endl; 
    #endif
    
    BN_vec_random(m);
    for(auto i = 0; i < m.size(); i++){ 
        BN_mod(m[i], m[i], pp.BN_MSG_SIZE, bn_ctx);
    }

    #ifdef DEMO
    cout << "Generate random policy vector >>>" << endl; 
    #endif
    
    BN_vec_random(policy);
    for(auto i = 0; i < policy.size(); i++){ 
        BN_mod(policy[i], policy[i], pp.BN_MSG_SIZE, bn_ctx);
    }

    #ifdef DEMO
    cout << "The result should be >>>" << endl; 
    #endif

    BN_vec_inner_product(result, m, policy); 
    BN_print(result, "result"); 


    IPFE_Enc(pp, mpk, m, CT);

    IPFE_FSK fsk; 
    IPFE_FSK_Derive(msk, policy, fsk); 

    IPFE_Dec(pp, fsk, CT, result_prime); 
    BN_print(result_prime, "result'"); 

    IPFE_PP_free(pp); 
    ECP_vec_free(mpk);
    BN_vec_free(msk);  
    IPFE_FSK_free(fsk);
    BN_vec_free(policy); 
    BN_vec_free(m); 
    BN_free(result);
    BN_free(result_prime); 
}


int main()
{  
    global_initialize(NID_X9_62_prime256v1);   

    SplitLine_print('-'); 
    cout << "IPFE test begins >>>>>>" << endl; 
    SplitLine_print('-'); 

    // the default LOG_LEN is 32
    size_t LOG_LEN = 32; 
    size_t MAP_TUNNING = 7; 
    size_t DEC_THREAD_NUM = 4;  
    // size_t TEST_NUM = 30000;  

    // choose MSG_LEN and DIMENTION_LEN satisfying the constraint MSG_LEN*2+DIMENTION <= LOG_LEN
    size_t MSG_LEN = 10; 
    size_t DIMENTION_LEN = 10; 

    test_IPFE(MSG_LEN, DIMENTION_LEN, LOG_LEN, MAP_TUNNING, DEC_THREAD_NUM);

    SplitLine_print('-'); 
    cout << "IPFE test finishes <<<<<<" << endl; 
    SplitLine_print('-'); 

    global_finalize();
    
    return 0; 
}



