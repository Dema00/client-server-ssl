#ifndef DATABASE_H
#define DATABASE_H
#endif

#include <sqlite3.h>
#include <string.h>
#include <iostream>

const char* get_user_psw(sqlite3* db, const char* username);
