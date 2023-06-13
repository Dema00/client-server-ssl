#ifndef UTILS_H
#define UTILS_H
#endif


#include <iostream>
#include <fstream>

#include <sqlite3.h>

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