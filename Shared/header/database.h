#ifndef DATABASE_H
#define DATABASE_H
#endif

#ifdef DEBUG
#define DEBUG_MSG(exp) do { exp } while( false )
#include <sstream>
#else
#define DEBUG_MSG(str) do { } while ( false )
#endif


#include <sqlite3.h>
#include <string.h>
#include <string>
#include <iostream>

#include <openssl/err.h>

int get_user_psw(sqlite3* db, std::string username, unsigned char* out);

int get_user_privkey(sqlite3* db, std::string username, unsigned char* out);

int get_user_pubkey(sqlite3* db, std::string username, unsigned char* out);
