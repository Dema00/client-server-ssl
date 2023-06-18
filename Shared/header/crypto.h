#ifndef CRYPTO_H
#define CRYPTO_H
#endif


#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include <iostream>

void handleErrors();


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

int hmac(const unsigned char* key, int key_len, const unsigned char* data,
    int data_len, unsigned char* md);