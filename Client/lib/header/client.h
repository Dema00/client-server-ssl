#ifndef CLIENT_H
#define CLIENT_H
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

class Client {
    private:
        int sd;
        struct sockaddr_in addr;
        socklen_t addr_size;

        const char *hostname;

        void clientProcess();
        void openConnection();

        void sendMessage(const char *message);

    public:
        Client(const char *hostname, int port);
        void startClient();
        void stopClient();

};