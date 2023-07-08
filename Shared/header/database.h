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
#include <ctime>
#include <vector>

int get_user_psw(sqlite3* db, std::string username, unsigned char* out);

int get_user_privkey(sqlite3* db, std::string username, unsigned char* out);

int get_user_pubkey(sqlite3* db, std::string username, unsigned char* out);

double get_user_balance(sqlite3* db, std::string username);

int get_user_id(sqlite3* db, std::string username);

std::string get_user_from_id(sqlite3* db, int id);

std::vector<std::string> get_history(sqlite3* db, std::string username, int t_num);

int insert_transaction(sqlite3* db, std::string sender_username, std::string recipient_username,double amount);


int check_user(sqlite3* db, std::string username);
