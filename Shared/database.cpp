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

double get_user_balance(sqlite3* db, std::string username) {
    sqlite3_stmt* stmt;

    char* query = sqlite3_mprintf("SELECT balance FROM users WHERE username = %Q\0",username.c_str());
        DEBUG_MSG(std::cout << query << std::endl;);
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);
    
    if (sqlite3_step(stmt) != SQLITE_ROW){
        std::cerr << username << " not foud! " << sqlite3_errmsg(db) << std::endl;
    }

    double balance = sqlite3_column_double(stmt, 0);
    
    sqlite3_finalize(stmt);

    return balance;
}

int get_user_id(sqlite3* db, std::string username) {
    sqlite3_stmt* stmt;

    char* query = sqlite3_mprintf("SELECT accountID FROM users WHERE username = %Q\0",username.c_str());
        DEBUG_MSG(std::cout << query << std::endl;);
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);
    
    if (sqlite3_step(stmt) != SQLITE_ROW){
        std::cerr << username << " not foud! " << sqlite3_errmsg(db) << std::endl;
    }

    int id = sqlite3_column_int(stmt, 0);
    
    sqlite3_finalize(stmt);

    return id;
}

std::string get_user_from_id(sqlite3* db, int id) {
    sqlite3_stmt* stmt;

    char* query = sqlite3_mprintf("SELECT username FROM users WHERE accountID = %i\0",id);
        DEBUG_MSG(std::cout << query << std::endl;);
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);
    
    if (sqlite3_step(stmt) != SQLITE_ROW){
        std::cerr << "id not foud! " << sqlite3_errmsg(db) << std::endl;
    }

    std::string ret((const char*)sqlite3_column_text(stmt, 0));
    
    sqlite3_finalize(stmt);

    return ret;
}

std::vector<std::string> get_history(sqlite3* db, std::string username, int t_num) {
    sqlite3_stmt* stmt;

    std::vector<std::string> vec;

    int id = get_user_id(db,username);
    char* query = sqlite3_mprintf("SELECT recipientID, amount, timestamp FROM transfers WHERE senderID = %i ORDER BY transferID DESC LIMIT %i\0",id,t_num);
        DEBUG_MSG(std::cout << query << std::endl;);
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string uname = get_user_from_id(db,sqlite3_column_int(stmt, 0));
        std::string amount = std::to_string(sqlite3_column_double(stmt, 1));
        std::string time = std::string((const char*)sqlite3_column_text(stmt, 2));

        vec.push_back("sent " + amount + " to " + uname + " on " + time);
    }
    
    sqlite3_finalize(stmt);

    return vec;
}

//-1 if absent, 0 if present
int check_user(sqlite3* db, std::string username) {
    sqlite3_stmt* stmt;

    char* query = sqlite3_mprintf("SELECT * FROM users WHERE username = %Q\0",username.c_str());
        DEBUG_MSG(std::cout << query << std::endl;);
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);
    
    if (sqlite3_step(stmt) != SQLITE_ROW){
        std::cerr << username << " not foud! " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return -1;
    }
    
    sqlite3_finalize(stmt);

    return 0;
}

void updateAccountBalance(sqlite3* db, const std::string& username, double amount) {
    sqlite3_stmt* stmt;

    char* statement = sqlite3_mprintf("UPDATE users SET balance = balance + %f WHERE username = %Q\0", amount, username.c_str());
    sqlite3_prepare_v2(db, statement, strlen(statement), &stmt, NULL);
    sqlite3_free(statement);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to update balance for " << username << ": " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_reset(stmt);
    sqlite3_finalize(stmt);
}

int getUserId(sqlite3* db, const std::string& username) {
    sqlite3_stmt* stmt;

    char* statement = sqlite3_mprintf("SELECT accountID FROM users WHERE username = %Q;\0", username.c_str());
    sqlite3_prepare_v2(db, statement, strlen(statement), &stmt, NULL);
    sqlite3_free(statement);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        std::cerr << "User " << username << " not found!" << std::endl;
        return -1;
    }

    int userID = sqlite3_column_int(stmt, 0);

    sqlite3_finalize(stmt);

    return userID;
}

void insertTransaction(sqlite3* db, const std::string& senderUsername, const std::string& recipientUsername, double amount) {
    int senderID = getUserId(db, senderUsername);
    if (senderID == -1) {
        return;
    }

    int recipientID = getUserId(db, recipientUsername);
    if (recipientID == -1) {
        return;
    }

    char timestamp[18];
    std::time_t now = std::time(0);
    std::tm* ptm = std::localtime(&now);
    std::strftime(timestamp, 19, "%d.%m.%Y%H:%M:%S", ptm);
    std::string timestampStr(timestamp);

    sqlite3_stmt* stmt;
    char* statement = sqlite3_mprintf("INSERT INTO transfers (senderID, amount, recipientID, timestamp) VALUES (%i, %f, %i, %Q);\0",
                                      senderID, amount, recipientID, timestampStr.c_str());
    sqlite3_prepare_v2(db, statement, strlen(statement), &stmt, NULL);
    sqlite3_free(statement);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to insert transaction: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
}

void processTransaction(sqlite3* db, const std::string& senderUsername, const std::string& recipientUsername, double amount) {
    updateAccountBalance(db, senderUsername, -amount);
    updateAccountBalance(db, recipientUsername, amount);
    insertTransaction(db, senderUsername, recipientUsername, amount);
}


