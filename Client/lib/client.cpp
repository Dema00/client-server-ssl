#include "header/client.h"
#include "../../Shared/header/utils.h"

void Client::openConnection() {
    if ( connect(this->sd, (struct sockaddr*)&this->addr, sizeof(this->addr)) != 0 )
	{
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
    
}

void Client::stopClient() {
    close(this->sd);
}