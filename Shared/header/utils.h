#ifndef UTILS_H
#define UTILS_H
#endif


#include <iostream>
#include <fstream>

std::string ReadFile(const std::string &filename) {
    std::ifstream file(filename);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}