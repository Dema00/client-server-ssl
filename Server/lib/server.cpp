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
    this->priv_key = std::vector<unsigned char>(std::istreambuf_iterator<char>(input), {});
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
        char msg [128];
        GetInput(msg);
        if (strcmp(msg, "quit") == 0) {
            this->status = TERMINATE;
            manager.detach();
            manager.~thread();
        }
    }
}

void Server::broadcast(MessageInterface* message) {
    for (auto & user : this->connected_users) {
            message->sendMessage(user.second);
        }
}  
void Server::broadcast(MessageInterface* message, std::string sender) {
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

    //retrieving user private key
    unsigned char pkey [2000]; 
    int k_size = get_user_pubkey(db,username,pkey);

    //receive nonce for ephemeral key exchange
    //REMEMBER CHECK IF THE RAND_BYTES IS INITIALIZED CORRECTLY!!!!
    auth_msg.receiveMessage(client);
    memset(nonce_buf,0,SHA256_DIGEST_LENGTH);
    memcpy(nonce_buf,auth_msg.getContents(),SHA256_DIGEST_LENGTH);
    auth_msg.clearContents();
    
    //ERSA keygen
    std::pair<EVP_PKEY*, EVP_PKEY*> keypair;
    keypair = generate_rsa_keypair();

    //ERSA pubkey serialization
    unsigned char pubkey_raw_buf [EVP_PKEY_size(keypair.first)];
    BIO* pubkey_bufio = BIO_new_mem_buf((const void*)pubkey_raw_buf,EVP_PKEY_size(keypair.first));
    PEM_write_bio_PUBKEY(pubkey_bufio,keypair.first);

    Message ephrsa_msg(2048);
    ephrsa_msg.addContents((const unsigned char*)pubkey_bufio,EVP_PKEY_size(keypair.first));
    ephrsa_msg.sendMessage(client);
    ephrsa_msg.clearContents();
    
    //Load and send Server Cert
    // copies all data into buffer
    std::ifstream srv_cert_buf( "../Keys/server_cert.pem", std::ios::binary );
    std::vector<unsigned char> srv_cert_vec(std::istreambuf_iterator<char>(srv_cert_buf), {});

    ephrsa_msg.addContents(srv_cert_vec.data(),srv_cert_vec.size());
    ephrsa_msg.sendMessage(client);
    ephrsa_msg.clearContents();


    //ERSA pubkey + nonce sign

    //receive symkey

    //delete pub and priv ERSA keysx


    //------------------------------------------------
    
    MessageInterface* comm_in = new AddRSA( new Message(512),this->priv_key.data());
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
        std::cout << "<" << client << ">" << (const char *)comm_in->getContents() << std::endl;
        comm_in->clearContents();
    }
    delete comm_in;
    return;
};