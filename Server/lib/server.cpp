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

    buffer symkey = this->symkeyExchange(client);

    //------------------------------------------------
    
    MessageInterface* comm_in = new AddAES256( new Message(512),symkey.data(),symkey.data());
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

buffer Server::symkeyExchange(int client) {
    Message ephrsa_msg(2048);
    //receive nonce for ephemeral key exchange
    //REMEMBER CHECK IF THE RAND_BYTES IS INITIALIZED CORRECTLY!!!!
    unsigned char nonce_buf [SHA256_DIGEST_LENGTH];
    ephrsa_msg.receiveMessage(client);
    memset(nonce_buf,0,SHA256_DIGEST_LENGTH);
    memcpy(nonce_buf,ephrsa_msg.getContents(),SHA256_DIGEST_LENGTH);
    ephrsa_msg.clearContents();
    
    //ERSA keygen
    std::pair<EVP_PKEY*, EVP_PKEY*> keypair;
    keypair = generate_rsa_keypair();

    //ERSA pubkey serialization---------
    BIO* pubkey_bufio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubkey_bufio,keypair.first);
    int pubkey_len = BIO_get_mem_data(pubkey_bufio,NULL);
    unsigned char serialized_pubkey [pubkey_len];
    BIO_read(pubkey_bufio, serialized_pubkey, pubkey_len);
        DEBUG_MSG(std::cout<<"RAW PKEY: \n" << 
            BIO_dump_fp (stdout, (const char*)serialized_pubkey,pubkey_len ) <<std::endl;);
        DEBUG_MSG(std::cout << "PUBKEY LEN " << pubkey_len << std::endl;);
    BIO_free(pubkey_bufio);
    //ERSA pubkey serialization END-----

    //ERSA pubkey send
    ephrsa_msg.addContents((const unsigned char*)serialized_pubkey,pubkey_len);
    ephrsa_msg.sendMessage(client);
    ephrsa_msg.clearContents();

    //Load Server Cert
    // copies all data into buffer
    std::ifstream srv_cert_buf( "../Keys/server_cert.pem", std::ios::binary );
    std::vector<unsigned char> srv_cert_vec(std::istreambuf_iterator<char>(srv_cert_buf), {});


    //ERSA pubkey + nonce sign

    //create pubkey+nonce buffer
    unsigned char pubkey_nonce [pubkey_len + SHA256_DIGEST_LENGTH];
    memmove(pubkey_nonce,serialized_pubkey,pubkey_len);
    memmove(pubkey_nonce + pubkey_len,nonce_buf,SHA256_DIGEST_LENGTH);

    int pubkey_nonce_len = pubkey_len + SHA256_DIGEST_LENGTH;
    DEBUG_MSG(std::cout<<"RAW PKEY + NONCE: \n" << 
            BIO_dump_fp (stdout, (const char*)pubkey_nonce,pubkey_nonce_len ) <<std::endl;);

    //sign the pubkey+nonce buffer
    unsigned char signed_pubkey_nonce [pubkey_nonce_len];
    int sign_size = sign(pubkey_nonce,pubkey_nonce_len,this->priv_key,signed_pubkey_nonce);
        DEBUG_MSG(std::cout<< sign_size <<"TRUE SIGNED PKEY + NONCE: \n" << 
            BIO_dump_fp (stdout, (const char*)signed_pubkey_nonce,sign_size ) <<std::endl;);

    //sending pubkey signed and server cert

    ephrsa_msg.clearContents();
    ephrsa_msg.addContents(signed_pubkey_nonce,sign_size);
    ephrsa_msg.addContents(srv_cert_vec.data(),srv_cert_vec.size());
        DEBUG_MSG(std::cout<<"SIGNED PKEY + NONCE: \n" << 
            BIO_dump_fp (stdout, (const char*)ephrsa_msg.getContents(),pubkey_nonce_len ) <<std::endl;);
    ephrsa_msg.sendMessage(client);
    ephrsa_msg.clearContents(); 

    //receive symkey

    MessageInterface* receive_symkey = new AddRSA ( new Message(512), keypair.second);

    receive_symkey->receiveMessage(client);

    std::vector<unsigned char>symkey;
    symkey.insert(symkey.begin(),receive_symkey->getContents(),receive_symkey->getContents()+32);

    //delete pub and priv ERSA keysx
    memset(serialized_pubkey,0,pubkey_len);
    EVP_PKEY_free(keypair.first);
    EVP_PKEY_free(keypair.second);
    return symkey;

};