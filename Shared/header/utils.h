#ifndef UTILS_H
#define UTILS_H
#endif


#include <iostream>
#include <fstream>
#include <cstring>
#include <limits>
#include <sstream>
#include <iomanip>


#include <sqlite3.h>

#include <openssl/evp.h>
#include <openssl/pem.h>


std::string ReadFile(const std::string &filename);

void GetInput(char* buf);

void print_EVP_PrivKEY(EVP_PKEY* key);

int getSingleNumberInput();

std::string getStringInputWithMaxSize(size_t maxSize);

double getDoubleInputWithMaxSize(size_t maxDigits);

float getFloatInput();