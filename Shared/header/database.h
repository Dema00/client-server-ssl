#ifndef DATABASE_H
#define DATABASE_H
#endif

#include <sqlite3.h>
#include <string.h>
#include <string>
#include <iostream>

void get_user_psw(sqlite3* db, std::string username, char* out);

int get_user_privkey(sqlite3* db, std::string username, unsigned char* out);

int get_user_pubkey(sqlite3* db, std::string username, unsigned char* out);
