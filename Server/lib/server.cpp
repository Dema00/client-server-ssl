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

    // copies all data into buffer
    std::ifstream input( "../Keys/private_server.pem", std::ios::binary );

    // copies all data into buffer
    std::vector<unsigned char>privkey_vec (std::istreambuf_iterator<char>(input), {});

    BIO* private_key_bio = BIO_new_mem_buf(privkey_vec.data(),privkey_vec.size());
    this->priv_key = PEM_read_bio_PrivateKey(private_key_bio,NULL,0,NULL);
    BIO_free(private_key_bio);

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

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    if (close(sd) != 0) {
        std::cerr << "ERROR WHILE CLOSING SOCKET " << sd << std::endl;
    }
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
        char msg [128];
        GetInput(msg);
        if (strcmp(msg, "quit") == 0) {
            this->status = TERMINATE;
            manager.detach();
            manager.~thread();
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
    //------------------------------------------------
    Message auth_msg(128);
    auth_msg.receiveMessage(client);
    std::string username((const char*)auth_msg.getContents());
    auth_msg.clearContents();

    bool login = false;

    //username handling

    if ( this->connected_users.count(username) == 0) {
        std::cout << ">>user " << username << " connected!" << std::endl;
        auth_msg.addContents((const unsigned char*)"USERNAME_OK",strlen("USERNAME_OK"));
        auth_msg.sendMessage(client);
        auth_msg.clearContents();
    } else
    {
        std::cout << ">>user " << username << " is already connected!" << std::endl;
        auth_msg.addContents((const unsigned char*)"USERNAME_ERR",strlen("USERNAME_ERR"));
        auth_msg.sendMessage(client);
        auth_msg.clearContents();
        close(client);
    }

    //send nonce for challenge response

    unsigned char nonce_buf [SHA256_DIGEST_LENGTH];
    RAND_bytes(nonce_buf, SHA256_DIGEST_LENGTH);
    auth_msg.addContents(nonce_buf, SHA256_DIGEST_LENGTH);
    auth_msg.sendMessage(client);
    auth_msg.clearContents();

    //password handling

    while (!login) {
        auth_msg.receiveMessage(client);
        unsigned char psw_hash [SHA256_DIGEST_LENGTH];
        memset(psw_hash,0,SHA256_DIGEST_LENGTH);
        get_user_psw(db,username,psw_hash);
        unsigned char hashed_psw_and_nonce [SHA256_DIGEST_LENGTH*2];
        memmove(hashed_psw_and_nonce,psw_hash,SHA256_DIGEST_LENGTH);
        memmove(hashed_psw_and_nonce+SHA256_DIGEST_LENGTH,psw_hash,SHA256_DIGEST_LENGTH);
        sha256(hashed_psw_and_nonce,SHA256_DIGEST_LENGTH*2,psw_hash);

        if (memcmp((const char*)auth_msg.getContents(),psw_hash, SHA256_DIGEST_LENGTH) == 0) {
            std::cout<< username <<" logged in succesfully!"<<std::endl;
            this->connected_users[username] = client;
            auth_msg.clearContents();
            auth_msg.addContents((const unsigned char*)"PASSWORD_OK",strlen("PASSWORD_OK"));
            auth_msg.sendMessage(client);
            login = true;
            
        } else {
            std::cerr<<"Wrong password!"<<std::endl;
            auth_msg.clearContents();
            auth_msg.addContents((const unsigned char*)"PASSWORD_ERR",strlen("PASSWORD_ERR"));
            auth_msg.sendMessage(client);
        }
        auth_msg.clearContents();
    }

    //------------------------------------------------
    
    MessageInterface* comm_in = new AddRSA( new Message(512),this->priv_key);
    while (login) {
        comm_in->receiveMessage(client);
        if (comm_in->getStatus() != OK) {
            std::cerr << "client " << username << " has disconnected" << std::endl;
            this->connected_users.erase(username);
            close(client);
            break;
        }
            DEBUG_MSG( std::cout << 
                BIO_dump_fp (stdout, 
                (const char *)comm_in->getContents(), 
                comm_in->getContentsSize()) << std::endl;);
        std::cout << "<" << username << "|" << client << ">" << (const char *)comm_in->getContents() << std::endl;
        comm_in->clearContents();
    }
    delete comm_in;
    return;
};