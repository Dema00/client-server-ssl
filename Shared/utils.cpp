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

int getSingleNumberInput() {
    int input;
    bool validInput = false;

    do {
        std::cin >> input;

        // Check if the input is a valid number
        if (std::cin.good() && std::cin.peek() == '\n') {
            validInput = true;
        } else {
            std::cout << "╟╼(✖)Invalid input. Please enter a single number." << std::endl << "├╼";
            // Clear the input buffer to handle any additional characters
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
    } while (!validInput);

    return input;
}

float getFloatInput() {
    float input;
    std::string inputStr;

    while (true) {
        std::cout << "Enter a floating-point number: ";
        std::getline(std::cin, inputStr);

        std::istringstream iss(inputStr);
        if (iss >> input && iss.eof()) {
            // Valid input
            break;
        } else {
            std::cout << "╟╼(✖)Invalid input. Please enter a valid floating-point number." << std::endl << "├╼";
            // Clear the input buffer
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
    }

    return input;
}

double getDoubleInputWithMaxSize(size_t maxDigits) {
    std::string input;

    std::cout << "  ├─╼Enter amount (maximum " << maxDigits << " digits): " << std::endl <<
                 "  ├╼";
    std::getline(std::cin, input);

    // Validate input size
    if (input.length() > maxDigits) {
        std::cout << "Input exceeds the maximum allowed size. Resizing..." << std::endl;
        input.resize(maxDigits);  // Trim input to the maximum size
    }

    // Convert string to double
    double value;
    std::istringstream iss(input);
    iss >> std::setprecision(maxDigits) >> value;

    return value;
}

std::string getStringInputWithMaxSize(size_t maxSize) {
    std::string input = "0";
    std::cin.ignore();
    std::getline(std::cin, input);

    // Validate input size
    if (input.length() > maxSize) {
        std::cout << "Input exceeds the maximum allowed size. Resizing..." << std::endl;
        input.resize(maxSize);  // Trim input to the maximum size
    }

    return input;
}