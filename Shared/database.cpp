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

std::vector<std::vector<unsigned char>> get_history(sqlite3* db, std::string username, int t_num) {
    sqlite3_stmt* stmt;

    std::vector<std::vector<unsigned char>> vec_ret;

    int id = get_user_id(db,username);
    char* query = sqlite3_mprintf("SELECT recipientID, amount, timestamp, senderID FROM transfers WHERE senderID = %i OR recipientID = %i ORDER BY transferID DESC LIMIT %i\0",id,id,t_num);
        DEBUG_MSG(std::cout << query << std::endl;);
    sqlite3_prepare_v2(db,query, strlen(query), &stmt, NULL);
    sqlite3_free(query);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::vector<unsigned char> vec;
        std::string uname = get_user_from_id(db,sqlite3_column_int(stmt, 0));
        std::string uname_sender = get_user_from_id(db,sqlite3_column_int(stmt, 3));
        double amount = sqlite3_column_double(stmt, 1);
        std::string time = std::string((const char*)sqlite3_column_text(stmt, 2));
        vec.insert(vec.end(),(const char*)&amount,(const char*)&amount + sizeof(double));
        vec.insert(vec.end(),time.data(),time.data()+time.size()+1);
        vec.insert(vec.end(),uname.data(),uname.data()+uname.size()+1);
        vec.insert(vec.end(),uname_sender.data(),uname_sender.data()+uname_sender.size()+1);
        vec_ret.push_back(vec);
    }
    
    sqlite3_finalize(stmt);

    return vec_ret;
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

    char timestamp[20];
    std::time_t now = std::time(0);
    std::tm* ptm = std::localtime(&now);
    std::strftime(timestamp, 20, "%d.%m.%Y %H:%M:%S", ptm);
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

void decryptSQLite3Database(const std::string& encryptedFilePath, const std::string& decryptedFilePath,
                            unsigned char* decryptionKey, unsigned char* iv) {
    // Open the encrypted database file
    std::ifstream encryptedFile(encryptedFilePath, std::ios::binary);
    if (!encryptedFile.is_open()) {
        std::cerr << "Failed to open the encrypted database file." << std::endl;
        return;
    }

    // Read the encrypted content into memory
    encryptedFile.seekg(0, std::ios::end);
    std::streampos encryptedSize = encryptedFile.tellg();
    encryptedFile.seekg(0, std::ios::beg);
    std::vector<unsigned char> encryptedContent(encryptedSize);
    encryptedFile.read(reinterpret_cast<char*>(encryptedContent.data()), encryptedSize);
    encryptedFile.close();

    unsigned char decryptedDb [encryptedContent.size()];

    int size = decrypt(encryptedContent.data(),encryptedContent.size(),decryptionKey, iv,decryptedDb);
    // Write the decrypted content to a new file
    std::ofstream decryptedFile(decryptedFilePath, std::ios::binary);
    if (!decryptedFile.is_open()) {
        std::cerr << "Failed to create the decrypted database file." << std::endl;
        return;
    }
    decryptedFile.write(reinterpret_cast<const char*>(decryptedDb), size);
    decryptedFile.close();
}

void encryptSQLite3Database(const std::string& originalFilePath, const std::string& encryptedFilePath,
                            unsigned char* encryptionKey, unsigned char* iv) {
    // Open the original SQLite3 database file
    std::ifstream originalFile(originalFilePath, std::ios::binary);
    if (!originalFile.is_open()) {
        std::cerr << "Failed to open the original database file." << std::endl;
        return;
    }

    // Read the original content into memory
    originalFile.seekg(0, std::ios::end);
    std::streampos originalSize = originalFile.tellg();
    originalFile.seekg(0, std::ios::beg);
    std::vector<unsigned char> originalContent(originalSize);
    originalFile.read(reinterpret_cast<char*>(originalContent.data()), originalSize);
    originalFile.close();


    unsigned char encryptedDb[originalContent.size()+16];

    // Perform encryption using your encryption algorithm or library
    int size = encrypt(originalContent.data(), originalContent.size(), encryptionKey, iv, encryptedDb);
    
    if (size <= 0) {
        std::cerr << "Encryption failed." << std::endl;
        return;
    }

    // Write the encrypted content to a new file
    std::ofstream encryptedFile(encryptedFilePath, std::ios::binary);
    if (!encryptedFile.is_open()) {
        std::cerr << "Failed to create the encrypted database file." << std::endl;
        return;
    }
    encryptedFile.write(reinterpret_cast<const char*>(encryptedDb), size);
    encryptedFile.close();
}

int open_db(std::string source_path, unsigned char* encryptionKey, unsigned char* iv, sqlite3** target) {
    std::string enc_path = source_path;
    enc_path.erase(enc_path.size()-3);
    enc_path = enc_path + "_encrypted";
    std::string dec_path = source_path;
    dec_path.erase(dec_path.size()-3);
    dec_path = dec_path + "_decrypted.db";
    decryptSQLite3Database(enc_path,dec_path,encryptionKey,iv);

    if (sqlite3_open_v2(dec_path.c_str(), target, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        std::cerr << "ERROR WHILE OPENING DATABASE";
        return 1;
    }

    return 0;
}

int close_db(std::string source_path, unsigned char* decryptionKey, unsigned char* iv, sqlite3* target) {
    std::string dec_path = source_path;
    dec_path.erase(dec_path.size()-3);
    dec_path = dec_path + "_decrypted.db";
    std::string enc_path = source_path;
    enc_path.erase(enc_path.size()-3);
    enc_path = enc_path + "_encrypted";
    encryptSQLite3Database(dec_path,enc_path,decryptionKey,iv);

    remove(dec_path.c_str());

    sqlite3_close_v2(target);

    return 0;
}

