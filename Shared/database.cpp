#include "header/database.h"

int get_user_psw(sqlite3* db, std::string username, unsigned char* out) {
    sqlite3_stmt* stmt;

    char* query = sqlite3_mprintf("SELECT password FROM users WHERE username = %Q\0",username.c_str());
        DEBUG_MSG(std::cout << query << std::endl;);
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);
    
    if (sqlite3_step(stmt) != SQLITE_ROW){
        std::cerr << username << " not foud! " << sqlite3_errmsg(db) << std::endl;
    }

    int size = sqlite3_column_bytes(stmt, 0);
    memmove(out,(unsigned char*)(sqlite3_column_blob(stmt, 0)),size);
    DEBUG_MSG(std::cout<<"HASH FROM DB: \n" << BIO_dump_fp (stdout, (const char *)out, size) <<std::endl;);
    
    sqlite3_finalize(stmt);

    return size;
}

int get_user_privkey(sqlite3* db, std::string username, unsigned char* out) {
    sqlite3_stmt* stmt;

    char* query = sqlite3_mprintf("SELECT pKey FROM users WHERE name = %Q\0",username.c_str());
        DEBUG_MSG(std::cout << query << std::endl;);
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);
    
    if (sqlite3_step(stmt) != SQLITE_ROW){
        std::cerr << username << " not foud! " << sqlite3_errmsg(db) << std::endl;
    }

    int size = sqlite3_column_bytes(stmt, 0);
    memmove(out,(unsigned char*)sqlite3_column_blob(stmt, 0),size);
    
    sqlite3_finalize(stmt);

    return size;
}

int get_user_pubkey(sqlite3* db, std::string username, unsigned char* out) {
    sqlite3_stmt* stmt;

    char* query = sqlite3_mprintf("SELECT pKey FROM users WHERE username = %Q\0",username.c_str());
        DEBUG_MSG(std::cout << query << std::endl;);
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);
    
    if (sqlite3_step(stmt) != SQLITE_ROW){
        std::cerr << username << " not foud! " << sqlite3_errmsg(db) << std::endl;
    }

    int size = sqlite3_column_bytes(stmt, 0);
    memmove(out,(unsigned char*)sqlite3_column_blob(stmt, 0),size);
    
    sqlite3_finalize(stmt);

    return size;
}

