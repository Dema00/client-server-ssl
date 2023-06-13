#ifndef SERVER_H
#define SERVER_H
#endif

#include "../../../Message/header/message.h"

#include <sqlite3.h>

#include <map>
#include <thread>

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>



class Server {
    private:
        // socket management
        int sd;
        struct sockaddr_in addr;
        socklen_t addr_size;

        // thread management
        std::map<int,std::thread> threads;

        // db management
        sqlite3* db;

        void openListener();

        void connectionManager();

        void sessionHandler(int client);

    public:
        Server(int portnum, const char* db_path);

        void startServer();
        void stopServer();

};