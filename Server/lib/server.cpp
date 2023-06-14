#include "header/server.h"
#include "../../Shared/header/utils.h"

Server::Server(int portnum, const char* db_path): threads() {
    this->sd = socket(AF_INET, SOCK_STREAM, 0);
    this->addr = {
        AF_INET, // sin_family
        htons(portnum), //sin_port
        {INADDR_ANY} //sin_addr.addr
    };
    this->addr_size = sizeof(this->addr);

    if (sqlite3_open_v2(db_path,&this->db,SQLITE_OPEN_READWRITE,NULL) != SQLITE_OK) {
        std::cerr<<"ERROR WHILE OPENING DATABASE";
        close(this->sd);
        abort();
    }

    this->status = RUN;
    
    std::cout<< "New server created with address: localhost:" << portnum <<std::endl;
};

void Server::startServer() {
    this->openListener();


    //assolutamente inutile
    std::string welcomeFile = "lib/ascii_art.txt";
	std::cout<<ReadFile(welcomeFile)<< std::endl;

    this->connectionManager();
};

void Server::stopServer() {

    for (auto & thread : this->threads) {
        thread.join();
    }

    if (close(this->sd) != 0) {
        std::cerr << "ERROR WHILE CLOSING SOCKET " << this->sd << std::endl;
    };
};

void Server::openListener(){
    if( bind(this->sd, (struct sockaddr*)&this->addr, this->addr_size) != 0) {
        std::cerr<<"PORT BINDING ERROR";
        close(this->sd);
        abort();
    }

    if( listen(this->sd, 10) != 0) {
        std::cerr<<"LISTENING CONFIG ERROR";
        close(this->sd);
        abort();
    }
};

void Server::serverControlPanel() {
    while(this->status == RUN) {
        char msg [256];
        GetInput(msg);
        if (strcmp(msg, "quit") == 0) {
            this->status = TERMINATE;
        }
    }
}

void Server::connectionManager() {
    threads.push_back(std::thread(&Server::serverControlPanel, this));
    while(this->status == RUN) {
        if (listen(this->sd, 5) != 0) {
            std::cerr << "ERROR WHILE LISTENING ON " << this->sd;;
        };

        int client = accept(this->sd, (struct sockaddr*)&this->addr, &this->addr_size);
        printf("Connection: %s:%d\n",inet_ntoa(this->addr.sin_addr), ntohs(this->addr.sin_port));

        threads.push_back(std::thread(&Server::sessionHandler, this, client));
    }
};

void Server::sessionHandler(int client) {
    Message* username = new Message(256,client);
    const char* psw = get_user_psw(this->db, username->getContents());
    Message* user_psw = new Message(256,client);
    bool logged = strncmp(psw,user_psw->getContents(), strlen(psw));
    while (logged) {
        Message* received = new Message(1024,client);
        if (received->getStatus() != OK) {
            std::cerr << "client " << username->getContents() << " has disconnected" << std::endl;
            connected_users.erase(username->getContents());
            break;
        }
        std::cout << "<" << username->getContents() << "> " << received->getContents() << std::endl;
        delete received;
    }
    return;
};