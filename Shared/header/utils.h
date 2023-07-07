#ifndef UTILS_H
#define UTILS_H
#endif


#include <iostream>
#include <fstream>

#include <sqlite3.h>

#include <openssl/evp.h>

int serializePublicKeyToUnsignedChar(EVP_PKEY *pkey, unsigned char **serialized, size_t *serialized_len) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        // Handle error
        return 0;
    }

    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        // Handle error
        return 0;
    }

    // Get the length of the serialized data
    size_t len = BIO_get_mem_data(bio, (char**)serialized);

    // Allocate memory for the serialized data
    *serialized = (unsigned char*)malloc(len);
    if (*serialized == NULL) {
        BIO_free(bio);
        // Handle error
        return 0;
    }

    // Read the serialized data into the buffer
    BIO_read(bio, *serialized, len);

    // Cleanup
    BIO_free(bio);

    *serialized_len = len;
    return 1;
}

EVP_PKEY* deserializePublicKeyFromUnsignedChar(const unsigned char* serialized, size_t serialized_len) {
    BIO *bio = BIO_new_mem_buf(serialized, serialized_len);
    if (bio == NULL) {
        // Handle error
        return NULL;
    }

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        BIO_free(bio);
        // Handle error
        return NULL;
    }

    // Cleanup
    BIO_free(bio);

    return pkey;
}


std::string ReadFile(const std::string &filename) {
    std::ifstream file(filename);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

void GetInput(char* buf) {
	std::string inputLine = "0";

	if (!std::getline(std::cin, inputLine)) {
		std::cerr << "Error reading input from keyboard.. " << std::endl;
	}
	strcpy(buf, inputLine.c_str());
}

void XOR(unsigned char* inBuf1,unsigned  char* inBuf2,unsigned  char*outBuf, int size)
{
    while(size--)
    {
        *outBuf++ = *inBuf1++ ^ *inBuf2++;
    }
}