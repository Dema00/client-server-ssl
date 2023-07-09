#include "./header/utils.h"

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

void print_EVP_PrivKEY(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
        char* buffer;
        long keySize = BIO_get_mem_data(bio, &buffer);
        std::cout << BIO_dump_fp(stdout,buffer,keySize);
        //std::cout << "RSA KEY:\n" << std::string(buffer, keySize) << std::endl;
    }
    else {
        std::cerr << "Error while writing the RSA key" << std::endl;
    }
    BIO_free(bio);
}