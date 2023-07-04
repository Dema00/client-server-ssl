#ifndef CLIENT_H
#define CLIENT_H
#endif

#include "../../../Message/header/message.h"
#include "../../../Shared/header/database.h"

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include<vector>

#include <iostream>
#include <fstream>
#include <thread>

class Client {
    private:
        const char *uname;
        int sd;
        struct sockaddr_in addr;
        socklen_t addr_size;

        sqlite3* db;

        const char *hostname;

        buffer priv_key;
        buffer pub_key;

        void clientProcess();
        void openConnection();

        void sendMessage(const char *message, std::size_t msg_size);
        
        void messagePrinter();

    public:
        Client(const char *hostname, int port, const char* uname, const char* db_path);
        void startClient();
        void stopClient();
        ~Client() {
            delete[] uname;
            delete[] hostname;
            sqlite3_close_v2(db);
        }


};