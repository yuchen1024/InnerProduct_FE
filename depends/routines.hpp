/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of PGC, developed by Yu Chen
* @paper      https://eprint.iacr.org/2019/319
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef __ROUTINES__
#define __ROUTINES__

#include "../global/global.hpp"

/* Big Number operations */

/* generate a random big integer mod order */
void BN_random(BIGNUM *&result)
{
    BN_priv_rand_range(result, order);
} 


/* save a 32-bytes big number (<2^256) in binary form */  
void BN_serialize(BIGNUM *&x, ofstream &fout)
{
    unsigned char buffer[BN_LEN];
    BN_bn2binpad(x, buffer, BN_LEN);
    fout.write(reinterpret_cast<char *>(buffer), BN_LEN);   // write to outfile
}

/* recover a ZZn element from binary file */
void BN_deserialize(BIGNUM *&x, ifstream &fin)
{
    char buffer[BN_LEN];
    fin.read(buffer, BN_LEN);
    BN_bin2bn(reinterpret_cast<unsigned char *>(buffer), BN_LEN, x);
}

void BN_mod_negative(BIGNUM *&a)
{ 
    BN_mod_sub(a, BN_0, a, order, bn_ctx); // return a = -a mod order
}


/* generate a vector of random big integers mod order */
void BN_vec_random(vector<BIGNUM *> vec_a)
{
    for(auto i = 0; i < vec_a.size(); i++){ 
        BN_random(vec_a[i]); 
    }
}

/* allocate memory for big integer */
void BN_vec_new(vector<BIGNUM *> &vec_a)
{
    for(auto i = 0; i < vec_a.size(); i++){
        vec_a[i] = BN_new(); 
    }
}

void BN_vec_free(vector<BIGNUM *> &vec_a)
{
    for(auto i = 0; i < vec_a.size(); i++){
        BN_free(vec_a[i]); 
    }
}

/* EC points operations */

/* generate a random EC points */
void ECP_random(EC_POINT *&result)
{
    BIGNUM *r = BN_new(); 
    BN_random(r);  
    EC_POINT_mul(group, result, r, NULL, NULL, bn_ctx);
    BN_free(r);
} 

/* generate a vector of random EC points */  
void ECP_vec_random(vector<EC_POINT *> vec_A)
{
    for(auto i = 0; i < vec_A.size(); i++){ 
        ECP_random(vec_A[i]); 
    }
}

/* allocate memory for a vector of EC points */
void ECP_vec_new(vector<EC_POINT *> &vec_A)
{
    for(auto i = 0; i < vec_A.size(); i++){
        vec_A[i] = EC_POINT_new(group); 
    }
}

/* free memory for a vector of EC points */
void ECP_vec_free(vector<EC_POINT *>& vec_A)
{
    for(auto i = 0; i < vec_A.size(); i++){
        EC_POINT_free(vec_A[i]); 
    }
}

/*  save a compressed ECn element in binary form */ 
void ECP_serialize(EC_POINT *&A, ofstream &fout)
{
    unsigned char buffer[POINT_LEN];
    EC_POINT_point2oct(group, A, POINT_CONVERSION_COMPRESSED, buffer, POINT_LEN, bn_ctx);
    // write to outfile
    fout.write(reinterpret_cast<char *>(buffer), POINT_LEN); 
}

/*  recover an ECn element from binary file */
void ECP_deserialize(EC_POINT *&A, ifstream &fin)
{
    unsigned char buffer[POINT_LEN];
    fin.read(reinterpret_cast<char *>(buffer), POINT_LEN); 
    EC_POINT_oct2point(group, A, buffer, POINT_LEN, bn_ctx);
}


/*  save a vector of 32-bytes big number (<2^256) in binary form */
void ECP_vec_serialize(vector<EC_POINT*> &vec_A, ofstream& fout)
{ 
    unsigned char buffer[POINT_LEN];
    for(auto i = 0; i < vec_A.size(); i++)
    {
        EC_POINT_point2oct(group, vec_A[i], POINT_CONVERSION_COMPRESSED, buffer, POINT_LEN, bn_ctx);
        fout.write(reinterpret_cast<char *>(buffer), POINT_LEN); // write to outfile
    } 
}

/* recover vector<ECn> from binary file, n is the size of vec_A */
void ECP_vec_deserialize(vector<EC_POINT*> &vec_A, ifstream &fin)
{   
    unsigned char buffer[POINT_LEN];
    for (auto i = 0; i < vec_A.size(); i++)
    {  
        fin.read(reinterpret_cast<char *>(buffer), POINT_LEN); 
        EC_POINT_oct2point(group, vec_A[i], buffer, POINT_LEN, bn_ctx); 
    }
}

/* single thread substract */
inline int EC_POINT_sub(EC_POINT *&r, EC_POINT *&a, EC_POINT *&b)
{
    EC_POINT *temp_ecp = EC_POINT_new(group);
    EC_POINT_copy(temp_ecp, b);  
    EC_POINT_invert(group, temp_ecp, bn_ctx);
    int result = EC_POINT_add(group, r, a, temp_ecp, bn_ctx);
    EC_POINT_free(temp_ecp); 
    return result;
}

/* multi thread substract */
inline int EC_POINT_sub_without_bnctx(EC_POINT *&r, EC_POINT *&a, EC_POINT *&b)
{
    EC_POINT* temp_ecp = EC_POINT_new(group);
    EC_POINT_copy(temp_ecp, b);  
    EC_POINT_invert(group, temp_ecp, NULL);
    int result = EC_POINT_add(group, r, a, temp_ecp, NULL);
    EC_POINT_free(temp_ecp); 
    return result;
}


/* vec_g = c * vec_g */ 
inline void ECP_vec_scalar(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_A, BIGNUM* &c)
{
    for (auto i = 0; i < vec_A.size(); i++) 
    {
        EC_POINT_mul(group, result[i], NULL, vec_A[i], c, bn_ctx); // result[i] = vec_g[i]^c
    } 
}


/* result[i] = A[i]*a[i] */ 
inline void ECP_vec_product(vector<EC_POINT *> &result, vector<EC_POINT *> &vec_A, vector<BIGNUM *> &vec_a)
{
    if (vec_A.size() != vec_a.size()) 
    {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    } 
    for (auto i = 0; i < vec_A.size(); i++) 
    {
        EC_POINT_mul(group, result[i], NULL, vec_A[i], vec_a[i], bn_ctx); 
    } 
}

/* result = sum_{i=1^n} a[i]*A[i] */ 
inline void ECP_vec_mul(EC_POINT* &result, vector<EC_POINT *> &vec_A, vector<BIGNUM *> &vec_a)
{
    if (vec_A.size() != vec_a.size()) {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    }
    EC_POINTs_mul(group, result, NULL, vec_A.size(), 
                  (const EC_POINT**)vec_A.data(), (const BIGNUM**)vec_a.data(), bn_ctx); 
}

/* c[i] = a[i]*b[i] mod order */ 
inline void BN_vec_product(vector<BIGNUM *> &result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
    if (vec_a.size() != vec_b.size()) 
    {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    }
    
    for (auto i = 0; i < vec_a.size(); i++) 
    {
        BN_mod_mul(result[i], vec_a[i], vec_b[i], order, bn_ctx); // product = (vec_a[i]*vec_b[i]) mod order
    }
}

void BN_vec_copy(vector<BIGNUM *> &vec_to, vector<BIGNUM *> &vec_from)
{
    if(vec_to.size() != vec_from.size()){
        cout << "size does not match" << endl;
    }
    else{
        for(auto i = 0; i < vec_to.size(); i++){
            BN_copy(vec_to[i], vec_from[i]); 
        }
    }
}

/* sum_i^n a[i]*b[i] */
inline void BN_vec_inner_product(BIGNUM *&result, vector<BIGNUM *> &vec_a, vector<BIGNUM *> &vec_b)
{
    BN_zero(result); // set result = 0

    BIGNUM *product = BN_new(); 

    if (vec_a.size() != vec_b.size()) 
    {
        cout << "vector size does not match!" << endl;
        exit(EXIT_FAILURE); 
    }   
    for (auto i = 0; i < vec_a.size(); i++) 
    {
        BN_mul(product, vec_a[i], vec_b[i], bn_ctx); // product = (vec_a[i]*vec_b[i]) mod order
        BN_add(result, result, product);     // result = (result+product) mod order
    }
    BN_mod(result, result, order, bn_ctx);
}

inline bool FILE_exist(const string& filename)
{
    bool existing_flag; 
    ifstream fin; 
    fin.open(filename);
    if(!fin)  existing_flag = false;    
    else existing_flag = true;
    return existing_flag; 
}

#endif

