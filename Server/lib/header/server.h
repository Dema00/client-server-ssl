#ifndef SERVER_H
#define SERVER_H
#endif

#include "../../../Message/header/message.h"
#include "../../../Shared/header/database.h"

#include <sqlite3.h>

#include <vector>
#include <thread>
#include <algorithm>
#include <map>
#include <atomic>

#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>


enum serverStatus{
    RUN,
    TERMINATE,
};



class Server {
    private:
        // socket management
        int sd;
        struct sockaddr_in addr;
        socklen_t addr_size;

        // thread management
        std::vector<std::thread> threads;

        // db management
        sqlite3* db;
        std::string db_path;

        // server private key
        EVP_PKEY* priv_key;
        
        // user management
        std::map<std::string,int> connected_users;

        // server management
        std::atomic<serverStatus> status;

        void openListener();

        void serverControlPanel();

        void connectionManager();
        buffer symkeyExchange(int client);
        void operationManager(MessageInterface* message,std::string username,int client);

        void sessionHandler(int client);

    public:
        // Disable copy constructor and assignment operator
        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;

        Server(int portnum, const char* db_path);
        ~Server() {
            EVP_PKEY_free(priv_key);
            sqlite3_close_v2(db);
            // Close the socket
            if (close(sd) != 0) {
                std::cerr << "ERROR WHILE CLOSING SOCKET " << sd << std::endl;
            }
        };

        void startServer();
        void stopServer();

};