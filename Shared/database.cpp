#include "header/database.h"

void get_user_psw(sqlite3* db, std::string username, char* out) {
    sqlite3_stmt* stmt;

    char* query = sqlite3_mprintf("SELECT password FROM users WHERE username = %Q",username.c_str());
    std::cout << query << std::endl;
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);
    
    if (sqlite3_step(stmt) != SQLITE_ROW){
        std::cerr << username << " not foud! " << sqlite3_errmsg(db) << std::endl;
    }
    strcpy(out,(char*)(sqlite3_column_text(stmt, 0)));
    
    sqlite3_finalize(stmt);
}

