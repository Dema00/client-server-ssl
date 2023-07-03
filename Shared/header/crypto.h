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

#include <iostream>

void handleErrors();


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

void hmac(const unsigned char* key, int key_len, const unsigned char* data,
    int data_len, unsigned char* md, unsigned int* md_len);

int rsa_encrypt(const unsigned char* key, int key_len, unsigned char *plaintext, int plaintext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv, unsigned char *ciphertext);

int rsa_decrypt(const unsigned char* key, int key_len, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv, unsigned char *plaintext);