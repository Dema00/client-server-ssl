#include "header/server.h"
#include "../../Shared/header/utils.h"

// Server constructor
Server::Server(int portnum, const char* db_path): threads() {
    if (std::getenv("HISTORY_SIZE") == NULL){
        std::cerr << "set environment variable HISTORY_SIZE" << std::endl;
        exit(1);
    }

    // Create a socket
    this->sd = socket(AF_INET, SOCK_STREAM, 0);

    this->db_path = std::string(db_path);

    // Set server address
    this->addr = {
        AF_INET, // sin_family
        htons(portnum), // sin_port
        {INADDR_ANY} // sin_addr.addr
    };
    this->addr_size = sizeof(this->addr);

    // Read private key from file
    std::ifstream input("../Keys/private_server.pem", std::ios::binary);
    std::vector<unsigned char> privkey_vec(std::istreambuf_iterator<char>(input), {});

    // Load private key into BIO
    BIO* private_key_bio = BIO_new_mem_buf(privkey_vec.data(), privkey_vec.size());

    // Read private key from BIO
    this->priv_key = PEM_read_bio_PrivateKey(private_key_bio, NULL, 0, NULL);

    // Free the BIO
    BIO_free(private_key_bio);

    //encryptSQLite3Database(db_path,"bank_encrypted",privkey_vec.data()+40,privkey_vec.data()+40);

    open_db(db_path,privkey_vec.data()+40,privkey_vec.data()+40, &this->db);

    // Set server status to RUN
    status.store(RUN);
    
    std::cout << "New server created with address: localhost:" << portnum << std::endl;
}

void Server::startServer() {
    this->openListener();

    // Print welcome message
    std::string welcomeFile = "lib/ascii_art.txt";
    std::cout << ReadFile(welcomeFile) << std::endl;

    // Start server control panel
    this->serverControlPanel();
}

void Server::stopServer() {
    // Read private key from file
    std::ifstream input("../Keys/private_server.pem", std::ios::binary);
    std::vector<unsigned char> privkey_vec(std::istreambuf_iterator<char>(input), {});

    close_db(db_path,privkey_vec.data()+40,privkey_vec.data()+40, this->db);

    // Join all threads
    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void Server::openListener() {
    // Bind the socket to the server address
    if (bind(this->sd, (struct sockaddr*)&this->addr, this->addr_size) != 0) {
        std::cerr << "PORT BINDING ERROR";
        close(this->sd);
        abort();
    }

    // Listen for incoming connections
    if (listen(this->sd, 10) != 0) {
        std::cerr << "LISTENING CONFIG ERROR";
        close(this->sd);
        abort();
    }
}

void Server::serverControlPanel() {
    // Start connection manager thread
    std::thread manager(&Server::connectionManager, this);

    // Process user input until the server status changes to TERMINATE
    while (status.load() == RUN) {
        char msg[128];
        GetInput(msg);
        if (strcmp(msg, "quit") == 0) {
            status.store(TERMINATE);
            stopServer();
            Message killer(8);
            killer.sendMessage(sd);
            manager.join();
        }
        if (strcmp(msg, "balance") == 0) {
            std::cout << "insert user:" << std::endl;
            GetInput(msg);
            std::cout << msg << "'s balance is: " << get_user_balance(db,std::string(msg)) << std::endl; 
        }
    }
}

void Server::connectionManager() {
    while (status.load() == RUN) {
        // Listen for incoming connections
        if (listen(this->sd, 5) != 0) {
            std::cerr << "ERROR WHILE LISTENING ON " << this->sd;
        }

        // Accept a new client connection
        int client = accept(this->sd, (struct sockaddr*)&this->addr, &this->addr_size);
        printf("Connection: %s:%d\n", inet_ntoa(this->addr.sin_addr), ntohs(this->addr.sin_port));

        // Start a new session handler thread for the client
        threads.push_back(std::thread(&Server::sessionHandler, this, client));
    }

    // Stop the server (should not reach this point)
    stopServer();
}

void Server::sessionHandler(int client) {
    // Authentication phase
    Message auth_msg(128);
    auth_msg.receiveMessage(client);
    std::string username((const char*)auth_msg.getContents());
    auth_msg.clearContents();

    bool login = false;

    // Handle username
    if (this->connected_users.count(username) == 0) {
        std::cout << ">>user " << username << " connected!" << std::endl;
        auth_msg.addContents((const unsigned char*)"USERNAME_OK", strlen("USERNAME_OK"));
        auth_msg.sendMessage(client);
        auth_msg.clearContents();
    } else {
        std::cout << ">>user " << username << " is already connected!" << std::endl;
        auth_msg.addContents((const unsigned char*)"USERNAME_ERR", strlen("USERNAME_ERR"));
        auth_msg.sendMessage(client);
        auth_msg.clearContents();
        close(client);
        return;
    }

    // Handle password
    while (!login) {
        // Send nonce for challenge response
        unsigned char nonce_buf[SHA256_DIGEST_LENGTH];
        RAND_bytes(nonce_buf, SHA256_DIGEST_LENGTH);
        auth_msg.addContents(nonce_buf, SHA256_DIGEST_LENGTH);
        auth_msg.sendMessage(client);
        auth_msg.clearContents();

        auth_msg.receiveMessage(client);
        unsigned char psw_hash[SHA256_DIGEST_LENGTH];
        memset(psw_hash, 0, SHA256_DIGEST_LENGTH);
        get_user_psw(db, username, psw_hash);
        unsigned char hashed_psw_and_nonce[SHA256_DIGEST_LENGTH*2];
        memmove(hashed_psw_and_nonce, psw_hash, SHA256_DIGEST_LENGTH);
        memmove(hashed_psw_and_nonce + SHA256_DIGEST_LENGTH, psw_hash, SHA256_DIGEST_LENGTH);
        sha256(hashed_psw_and_nonce, SHA256_DIGEST_LENGTH*2, psw_hash);

        if (memcmp((const char*)auth_msg.getContents(), psw_hash, SHA256_DIGEST_LENGTH) == 0) {
            std::cout << username << " logged in successfully!" << std::endl;
            this->connected_users[username] = client;
            auth_msg.clearContents();
            auth_msg.addContents((const unsigned char*)"PASSWORD_OK", strlen("PASSWORD_OK"));
            auth_msg.sendMessage(client);
            login = true;
        } else {
            std::cerr << "Wrong password!" << std::endl;
            auth_msg.clearContents();
            auth_msg.addContents((const unsigned char*)"PASSWORD_ERR", strlen("PASSWORD_ERR"));
            auth_msg.sendMessage(client);
        }
        auth_msg.clearContents();
    }

    // Perform symmetric key exchange
    buffer symkey = this->symkeyExchange(client);

    // Initialize message communication with encryption and integrity protection
    MessageInterface* comm = new AddTimestamp(new AddAES256(new AddMAC(new Message(512), symkey.data()), symkey.data(), symkey.data()));

    while (login && status.load() == RUN) {

        // Receive client's choice
        comm->receiveMessage(client);
        DEBUG_MSG(std::cout<< "received msg" << std::endl;);
        // Check if client has disconnected or wants to quit
        int quit = memcmp(comm->getContents(),"QUIT",5);
        if (comm->getStatus() !=OK || quit == 0) {
            std::cerr << "client " << username << " has disconnected" << std::endl;
            login = false;
            this->connected_users.erase(username);
            close(client);
            break;
        }

        DEBUG_MSG(std::cout << 
            BIO_dump_fp(stdout, (const char*)comm->getContents(), comm->getContentsSize()) << std::endl;);

        std::cout << "<" << username << "|" << client << ">" << (const char*)comm->getContents() << std::endl;

        // Manage the selected operation
        this->operationManager(comm, username, client);

        comm->clearContents();
    }

    delete comm;
    return;
}

void manageTransfer(MessageInterface* message, std::string username, int client, sqlite3* db) {
    
    message->receiveMessage(client);
    // Find recipient in the database
    std::string recipient_username((const char*)message->getContents()+sizeof(double));
    if (check_user(db, recipient_username) != 0) {
        message->clearContents();
        message->addContents((const unsigned char*)"RECIPIENT_ERROR", 16);
        message->sendMessage(client);
        message->clearContents();
        return;
    }
    message->clearContents();

    double amount = 0;
    memmove((unsigned char*)&amount, message->getContents(),sizeof(double));
    double balance = get_user_balance(db, username);

    if (amount > balance) {
        message->clearContents();
        message->addContents((const unsigned char*)"NOT_ENOUGH_MONEY", 17);
        message->sendMessage(client);
        message->clearContents();
        return;
    } else {
        processTransaction(db, username, recipient_username, amount);
        // ACK
        message->clearContents();
        message->addContents((const unsigned char*)"TRANSFER_DONE", 14);
        message->sendMessage(client);
        message->clearContents();
    }
    
}

void manageBalance(MessageInterface* message, std::string username, int client, sqlite3* db) {
    int id = get_user_id(db, username);
    double balance = get_user_balance(db, username);

    message->clearContents();
    message->addContents((const unsigned char*)&id,sizeof(int));
    message->addContents((const unsigned char*)&balance,sizeof(double));
    message->sendMessage(client);

}

void manageHistory(MessageInterface* message, std::string username, int client, sqlite3* db) {
    int n_transactions = stoi(std::string(std::getenv("HISTORY_SIZE")));
    std::vector<std::vector<unsigned char>> history = get_history(db, username, n_transactions);
    n_transactions = history.size();
    message->addContents((unsigned char*)&n_transactions,sizeof(int));
    for (auto& transaction : history) {
        message->addContents(transaction.data(), transaction.size());
    }

    message->sendMessage(client);
    message->clearContents();
}

void Server::operationManager(MessageInterface* message, std::string username, int client) {
    std::string input((const char*)message->getContents());
    message->clearContents();

    int value = stoi(input);
    switch (value) {
        case 1:
            manageBalance(message, username, client, db);
            break;
        case 2:
            manageTransfer(message, username, client, db);
            break;
        case 3:
            manageHistory(message, username, client, db);
            break;
        default:
            std::cout << "Unknown selection." << std::endl;
    }

    message->clearContents();
}

// Symmetric key exchange between server and client
buffer Server::symkeyExchange(int client) {
    Message ephrsa_msg(2048);

    // Receive nonce for ephemeral key exchange
    unsigned char nonce_buf[SHA256_DIGEST_LENGTH];
    ephrsa_msg.receiveMessage(client);
    memset(nonce_buf, 0, SHA256_DIGEST_LENGTH);
    memcpy(nonce_buf, ephrsa_msg.getContents(), SHA256_DIGEST_LENGTH);
    ephrsa_msg.clearContents();

    // Generate RSA key pair
    std::pair<EVP_PKEY*, EVP_PKEY*> keypair;
    keypair = generate_rsa_keypair();

    // Serialize RSA public key
    BIO* pubkey_bufio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubkey_bufio, keypair.first);
    int pubkey_len = BIO_get_mem_data(pubkey_bufio, NULL);
    unsigned char serialized_pubkey[pubkey_len];
    BIO_read(pubkey_bufio, serialized_pubkey, pubkey_len);
    BIO_free(pubkey_bufio);

    // Send RSA public key to client
    ephrsa_msg.addContents((const unsigned char*)serialized_pubkey, pubkey_len);
    ephrsa_msg.sendMessage(client);
    ephrsa_msg.clearContents();

    // Load server certificate
    std::ifstream srv_cert_buf("../Keys/server_cert.pem", std::ios::binary);
    std::vector<unsigned char> srv_cert_vec(std::istreambuf_iterator<char>(srv_cert_buf), {});

    // Sign RSA public key + nonce with server private key
    unsigned char pubkey_nonce[pubkey_len + SHA256_DIGEST_LENGTH];
    memmove(pubkey_nonce, serialized_pubkey, pubkey_len);
    memmove(pubkey_nonce + pubkey_len, nonce_buf, SHA256_DIGEST_LENGTH);
    int pubkey_nonce_len = pubkey_len + SHA256_DIGEST_LENGTH;

    unsigned char signed_pubkey_nonce[pubkey_nonce_len];
    int sign_size = sign(pubkey_nonce, pubkey_nonce_len, this->priv_key, signed_pubkey_nonce);

    // Send signed RSA public key + nonce and server certificate
    ephrsa_msg.clearContents();
    ephrsa_msg.addContents(signed_pubkey_nonce, sign_size);
    ephrsa_msg.addContents(srv_cert_vec.data(), srv_cert_vec.size());
    ephrsa_msg.sendMessage(client);
    ephrsa_msg.clearContents(); 

    // Receive symmetric key from client
    MessageInterface* receive_symkey = new AddRSA(new Message(512), keypair.second);
    receive_symkey->receiveMessage(client);

    // Extract symmetric key from received message
    std::vector<unsigned char> symkey;
    symkey.insert(symkey.begin(), receive_symkey->getContents(), receive_symkey->getContents() + 64);

    delete receive_symkey;

    // Clean up RSA keys
    memset(serialized_pubkey, 0, pubkey_len);
    EVP_PKEY_free(keypair.first);
    EVP_PKEY_free(keypair.second);

    return symkey;
}
