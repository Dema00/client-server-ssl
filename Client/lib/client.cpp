#include "header/client.h"
#include "../../Shared/header/utils.h"

void Client::openConnection() {
    if ( connect(this->sd, (struct sockaddr*)&this->addr, sizeof(this->addr)) != 0 )
	{   
        std::cerr << "FAILED TO CONNECT" << "\n Is the server running?";
		close(this->sd);
		abort();
	}
    printf("Connected with hostname %s and port %i \n", this->hostname, this->addr.sin_port);
}

Client::Client(const char *hostname, int port) {
    this->hostname = hostname;
    this->sd = socket(AF_INET, SOCK_STREAM, 0);
    this->addr = {
        AF_INET, // sin_family
        htons(port) //sin_port
    };
    inet_pton(AF_INET,this->hostname,&(this->addr.sin_addr));
}

void Client::startClient() {
    this->openConnection();

    //assolutamente inutile
    std::string welcomeFile = "lib/ascii_art.txt";
	std::cout<<ReadFile(welcomeFile)<< std::endl;

    this->clientProcess();
    
}

void Client::stopClient() {
    close(this->sd);
}

void Client::sendMessage(const char* message, std::size_t msg_size) {
    Message to_send = Message(msg_size);
    to_send.addContents(message);
    to_send.sendMessage(this->sd);
}

void Client::clientProcess() {
    while(1) {
        char msg [1024];
        GetInput(msg);
        this->sendMessage(msg, 1024);
    }
}