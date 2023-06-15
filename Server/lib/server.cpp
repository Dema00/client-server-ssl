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

    this->serverControlPanel();
};

void Server::stopServer() {

    for (auto & thread : this->threads) {
        thread.detach();
        thread.~thread();
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
    std::thread manager(&Server::connectionManager, this);
    while(this->status == RUN) {
        char msg [1024];
        GetInput(msg);
        if (strcmp(msg, "quit") == 0) {
            this->status = TERMINATE;
            manager.detach();
            manager.~thread();
        }
    }
}

void Server::broadcast(Message* message) {
    for (auto & user : this->connected_users) {
            message->sendMessage(user.second);
        }
}  
void Server::broadcast(Message* message, std::string sender) {
    for (auto & user : this->connected_users) {
            if (user.first != sender) {
                message->sendMessage(user.second);
            }
        }
}  

void Server::connectionManager() {
    while(1) {
        if (listen(this->sd, 5) != 0) {
            std::cerr << "ERROR WHILE LISTENING ON " << this->sd;;
        };

        int client = accept(this->sd, (struct sockaddr*)&this->addr, &this->addr_size);
        printf("Connection: %s:%d\n",inet_ntoa(this->addr.sin_addr), ntohs(this->addr.sin_port));

        threads.push_back(std::thread(&Server::sessionHandler, this, client));
    }
};

void Server::sessionHandler(int client) {
    char psw[1024];
    Message* un_msg = new Message(1024,client);
    std::cout << (const char*)un_msg->getContents() << std::endl;
    std::string username((const char*)un_msg->getContents());
    std::cout << username << std::endl;
    delete un_msg;

    get_user_psw(this->db, username, psw);

    Message* up_msg = new Message(1024,client);
    std::string user_pass((const char*)up_msg->getContents());
    bool logged = strncmp(psw,user_pass.c_str(),strlen(psw)) == 0;

    if ( this->connected_users.count(username) == 0) {
        this->connected_users[username] = client;
        std::cout << ">>user " << username << " logged in!" << std::endl;
    } else
    {
        std::cout << ">>user " << username << " is already logged in!" << std::endl;
        logged = false;
        Message bye(1024);
        bye.addContents((const unsigned char *)"user is already logged in");
        bye.sendMessage(client);
        close(client);
    }
    while (logged) {
        Message* received = new Message(1024,client);
        if (received->getStatus() != OK) {
            std::cerr << "client " << username << " has disconnected" << std::endl;
            this->connected_users.erase(username);
            close(client);
            delete received;
            break;
        }
        received->addContentsBeginning((const unsigned char *)" : ");
        received->addContentsBeginning((const unsigned char *)username.c_str());
        std::cout << received->getContents() << std::endl;
        this->broadcast(received, username);
        std::cout << "<" << client << ">" << received->getContents() << std::endl;

        delete received;
    }
    return;
};