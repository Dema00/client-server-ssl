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

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>

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
        
        // user management
        std::map<std::string,int> connected_users;

        // server management
        serverStatus status;

        void openListener();

        void serverControlPanel();

        void connectionManager();

        void broadcast(MessageInterface* message);
        void broadcast(MessageInterface* message, std::string sender);

        void sessionHandler(int client);

    public:
        Server(int portnum, const char* db_path);

        void startServer();
        void stopServer();

};