#ifndef SERVER_H
#define SERVER_H
#endif

#include "../../../Message/header/message.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>

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

        pthread_t thread_id;

        void openListener();

        void connectionManager();

        static void *sessionHandler(void* client);

    public:
        Server(int portnum);

        void startServer();
        void stopServer();

};