#include "header/database.h"

const char* get_user_psw(sqlite3* db, const char* username) {
    sqlite3_stmt* stmt;

    char* query = sqlite3_mprintf("SELECT password FROM users WHERE username = %Q",username);
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);
    
    if (sqlite3_step(stmt) != SQLITE_ROW){
        std::cerr << username << " not foud! " << sqlite3_errmsg(db) << std::endl;
        return NULL;
    }
    const char* psw = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    
    sqlite3_finalize(stmt);
    return psw;
}