#include "header/server.h"
#include "../../Shared/header/utils.h"

void Server::openListener(){
    if( bind(this->sd, (struct sockaddr*)&this->addr, this->addr_size) != 0) {
        std::cerr<<"PORT BINDING ERROR";
        close(this->sd);
        abort();
    }

    if( listen(sd, 10) != 0) {
        std::cerr<<"LISTENING CONFIG ERROR";
        close(sd);
        abort();
    }
};

void Server::connectionManager() {
    while(true) {
        if (listen(this->sd, 5) != 0) {
            std::cerr << "ERROR WHILE LISTENING ON " << this->sd;;
        };

        int client = accept(this->sd, (struct sockaddr*)&this->addr, &this->addr_size);
        printf("Connection: %s:%d\n",inet_ntoa(this->addr.sin_addr), ntohs(this->addr.sin_port));

        if (pthread_create(&this->thread_id, NULL, this->sessionHandler, (void*)&client)) {
			std::cout << "Error starting session handler thread... did you compile with the right flag?" << std::endl;
			close(client);
		}else {
			pthread_detach(this->thread_id);
		}

    }
};

void *Server::sessionHandler(void *client) {
    int sd = *((int*)client);
    while (1) {
        Message* received = new Message(1024,sd);
        if (received->getStatus() != OK) {
            break;
        }
        std::cout << "<" << sd  << "> " << received->getContents() << std::endl;
        delete received;
    }
};

void Server::startServer() {
    this->openListener();


    //assolutamente inutile
    std::string welcomeFile = "lib/ascii_art.txt";
	std::cout<<ReadFile(welcomeFile)<< std::endl;

    this->connectionManager();
};

void Server::stopServer() {
    if (close(this->sd) != 0) {
        std::cerr << "ERROR WHILE CLOSING SOCKET " << this->sd << std::endl;
    };
}

Server::Server(int portnum) {
    this->sd = socket(AF_INET, SOCK_STREAM, 0);
    this->addr = {
        AF_INET, // sin_family
        htons(portnum), //sin_port
        {INADDR_ANY} //sin_addr.addr
    };
    this->addr_size = sizeof(this->addr);
    std::cout<< "New server created on port: " << portnum <<std::endl;
};