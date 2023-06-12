#ifndef SERVER_H
#define SERVER_H
#endif

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
        int sd;
        struct sockaddr_in addr;
        socklen_t addr_size;

        void openListener();

        void serverProcess();

    public:
        Server(int portnum);

        void startServer();
        void stopServer();

};