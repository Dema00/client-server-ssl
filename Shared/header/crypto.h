#ifndef CRYPTO_H
#define CRYPTO_H
#endif

#ifdef DEBUG
#define DEBUG_MSG(exp) do { exp } while( false )
#include <sstream>
#else
#define DEBUG_MSG(str) do { } while ( false )
#endif


#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
 

#include <iostream>

void handleErrors();


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

void hmac(const unsigned char* key, int key_len, const unsigned char* data,
    int data_len, unsigned char* md, unsigned int* md_len);

int rsa_encrypt(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv, unsigned char *ciphertext);

int rsa_decrypt(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv, unsigned char *plaintext);

std::pair<EVP_PKEY*,EVP_PKEY*> generate_rsa_keypair();

void verify_cert(X509* ca_cert, X509_CRL* crl, X509* cert);

void verify_signature(unsigned char* sig, int sig_size,
    unsigned char* to_verify, int to_verify_size, X509* cert);

void sign(unsigned char* plaintext, int plaintext_len, EVP_PKEY* priv_key, unsigned char* signed_msg);

void sha256(const unsigned char* input, int len, unsigned char* out);
