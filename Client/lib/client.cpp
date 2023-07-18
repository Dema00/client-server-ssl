#include "header/client.h"
#include "../../Shared/header/utils.h"

void Client::openConnection() {
    if (connect(this->sd, (struct sockaddr*)&this->addr, sizeof(this->addr)) != 0) {
        std::cerr << "╰╼(✖)Failed to connect, " << " is the server running?";
        close(this->sd);
        exit(1);
    }
    printf("Connected with hostname %s and port %i \n", this->hostname, this->addr.sin_port);
}

Client::Client(const char* hostname, int port, const char* uname, const char* db_path) {
    this->uname = uname;
    this->hostname = hostname;
    this->sd = socket(AF_INET, SOCK_STREAM, 0);
    this->addr = {
        AF_INET,          // sin_family
        htons(port)       // sin_port
    };
    inet_pton(AF_INET, this->hostname, &(this->addr.sin_addr));

    if (sqlite3_open_v2(db_path, &this->db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        std::cerr << "╰╼(✖)Cannot open database";
        close(this->sd);
        exit(1);
    }

    unsigned char pkey[2000];
    memset(pkey, 0, 2000);
    int k_size = get_user_privkey(db, uname, pkey);
    BIO* private_key_bio = BIO_new_mem_buf(pkey, k_size);
    this->priv_key = PEM_read_bio_PrivateKey(private_key_bio, NULL, 0, NULL);
    BIO_free(private_key_bio);

    //DEBUG_MSG(print_EVP_PrivKEY(this->priv_key););

    std::ifstream input("../Keys/public_server.pem", std::ios::binary);
    std::vector<unsigned char> pubkey_vec(std::istreambuf_iterator<char>(input), {});

    BIO* public_key_bio = BIO_new_mem_buf(pubkey_vec.data(), pubkey_vec.size());
    this->pub_key = PEM_read_bio_PUBKEY(public_key_bio, NULL, 0, NULL);

    if (this->pub_key == NULL) {
        std::cerr << "╰╼(✖)Failed to open the public RSA key" << std::endl;
        exit(1);
    }
    BIO_free_all(public_key_bio);
}

void Client::startClient() {
    this->openConnection();

    // Print welcome message
    std::string welcomeFile = "lib/ascii_art.txt";
    std::cout << ReadFile(welcomeFile) << std::endl;

    std::cout << "╭──────╼ Hello " << uname << ", welcome back!" << std::endl;

    this->clientLogin();

    std::pair<buffer,buffer> symkeys = this->symKeyEstablishment();

    this->clientProcess(symkeys);
}

std::pair<buffer,buffer> Client::symKeyEstablishment() {
    Message ephrsa(2048);

    // Send nonce for ephemeral key exchange
    ephrsa.clearContents();
    unsigned char nonce[SHA256_DIGEST_LENGTH];
    memset(nonce, 0, SHA256_DIGEST_LENGTH);
    RAND_bytes(nonce, SHA256_DIGEST_LENGTH);
    ephrsa.addContents(nonce, SHA256_DIGEST_LENGTH);
    ephrsa.sendMessage(sd);
    ephrsa.clearContents();

    // Receive ERSA pubkey
    ephrsa.receiveMessage(sd);

    BIO* eph_pub_key_bio = BIO_new_mem_buf(ephrsa.getContents(), 451);
    EVP_PKEY* ephrsa_pubkey = PEM_read_bio_PUBKEY(eph_pub_key_bio, NULL, 0, NULL);
    BIO_free(eph_pub_key_bio);
    int eph_pubkey_len = 451;

    unsigned char eph_pubkey_raw[eph_pubkey_len];
    memmove(eph_pubkey_raw, ephrsa.getContents(), eph_pubkey_len);
    if (!ephrsa_pubkey) {
        std::cerr << "╰╼(✖)EPHRSA PUBKEY returned NULL\n";
        exit(1);
    }
    ephrsa.clearContents();

    // Certificate verification
    // Verify server cert by loading CA's certificate
    std::string cacert_file_name = "../Keys/CA_cert.pem";
    FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
    if (!cacert_file) {
        std::cerr << "╰╼(✖): cannot open file '" << cacert_file_name << "' (missing?)\n";
        exit(1);
    }
    DEBUG_MSG(std::cout << "RAW CA CERT: \n" << BIO_dump_fp(stdout, (const char*)cacert_file, 1000) << std::endl;);
    X509* ca_cert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if (!ca_cert) {
        std::cerr << "╰╼(✖)PEM_read_X509 returned NULL\n";
        exit(1);
    }

    // Load the CRL
    std::string crl_file_name = "../Keys/CA_crl.pem";
    FILE* crl_file = fopen(crl_file_name.c_str(), "r");
    DEBUG_MSG(std::cout << "RAW CA CRL: \n" << BIO_dump_fp(stdout, (const char*)crl_file, 1000) << std::endl;);
    if (!crl_file) {
        std::cerr << "╰╼(✖)Cannot open file '" << crl_file_name << "' (missing?)\n";
        exit(1);
    }
    X509_CRL* ca_crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if (!ca_crl) {
        std::cerr << "╰╼(✖)PEM_read_X509_CRL returned NULL\n";
        exit(1);
    }

    // Receive srv_cert and pubkey+nonce signature
    ephrsa.receiveMessage(sd);
    DEBUG_MSG(std::cout << "SRV_CERT: \n" << BIO_dump_fp(stdout, (const char*)ephrsa.getContents() + eph_pubkey_len + 32, ephrsa.getContentsSize() - eph_pubkey_len - 32) << std::endl;);
    BIO* srv_cert_bio = BIO_new_mem_buf(ephrsa.getContents() + 256, ephrsa.getContentsSize() - 256);
    ephrsa.clearContents();
    X509* srv_cert = PEM_read_bio_X509(srv_cert_bio, NULL, 0, NULL);
    BIO_free(srv_cert_bio);

    verify_cert(ca_cert, ca_crl, srv_cert);

    X509_CRL_free(ca_crl);
    X509_free(ca_cert);

    // Verify ERSA pubkey+nonce signature
    unsigned char pubkey_nonce[eph_pubkey_len + 32];
    memmove(pubkey_nonce, eph_pubkey_raw, eph_pubkey_len);
    memmove(pubkey_nonce + eph_pubkey_len, nonce, 32);

    DEBUG_MSG(std::cout << "UNSIGNED PKEY+NONCE: \n" << BIO_dump_fp(stdout, (const char*)pubkey_nonce, 451 + 32) << std::endl;);
    DEBUG_MSG(std::cout << "RECEIVED SIGN: \n" << BIO_dump_fp(stdout, (const char*)ephrsa.getContents(), 256) << std::endl;);

    verify_signature(ephrsa.getContentsMut(), 256, pubkey_nonce, eph_pubkey_len + 32, srv_cert);
    ephrsa.clearContents();
    X509_free(srv_cert);

    //Generate and send the symmetric key
    unsigned char symkey[512];
    RAND_bytes(symkey, 64+64);

    MessageInterface* symkey_send = new AddRSA(new Message(64), ephrsa_pubkey);
    symkey_send->addContents(symkey, 64+64);
    symkey_send->sendMessage(sd);
    symkey_send->clearContents();
    delete symkey_send;

    // Delete the pubkey
    memset(eph_pubkey_raw, 0, eph_pubkey_len);
    EVP_PKEY_free(ephrsa_pubkey);

    std::vector<unsigned char> symkey_buf;
    std::vector<unsigned char> mackey_buf;
    symkey_buf.insert(symkey_buf.begin(), symkey, symkey + 64);
    mackey_buf.insert(mackey_buf.begin(), symkey+64, symkey +64 +64);

    return {symkey_buf,mackey_buf};
}

void Client::clientLogin() {
    bool login = false;

    // Send username
    Message auth(128);
    auth.addContents((const unsigned char*)uname, strlen(uname));
    auth.sendMessage(sd);
    auth.clearContents();

    // Receive response for username
    auth.receiveMessage(sd);
    if (strcmp((const char*)auth.getContents(), "USERNAME_OK") != 0) {
        std::cerr << "╰╼(✖)User is already logged in" << std::endl;
        close(this->sd);
        exit(1);
    }
    auth.clearContents();
    std::cout << "╰─┬─╼Insert the password for " << uname << ":" << std::endl;
    // Password authentication
    char psw[128];
    while (!login) {

        // Receive nonce for challenge response
        auth.receiveMessage(sd);
        unsigned char nonce[SHA256_DIGEST_LENGTH];
        memcpy(nonce, auth.getContents(), SHA256_DIGEST_LENGTH);

        std::cout << "  ├╼";
        memset(psw, 0, 128);
        GetInput(psw);

        unsigned char hashed_psw[SHA256_DIGEST_LENGTH];
        unsigned char hashed_psw_and_nonce[SHA256_DIGEST_LENGTH * 2];
        sha256((unsigned char*)psw, strlen(psw), hashed_psw);
        memmove(hashed_psw_and_nonce, hashed_psw, SHA256_DIGEST_LENGTH);
        memmove(hashed_psw_and_nonce + SHA256_DIGEST_LENGTH, hashed_psw, SHA256_DIGEST_LENGTH);
        sha256(hashed_psw_and_nonce, SHA256_DIGEST_LENGTH * 2, hashed_psw);
        auth.clearContents();
        auth.addContents(hashed_psw, SHA256_DIGEST_LENGTH);
        auth.sendMessage(sd);
        auth.clearContents();
        auth.receiveMessage(sd);
        if (strcmp((const char*)auth.getContents(), "PASSWORD_OK") == 0) {
            std::cerr << "  ├╼(✓)Logged in successfully!" << std::endl;
            login = true;
        } else {
            std::cerr << "  ╟╼(✖)Wrong password!" << std::endl;
        }
    }
    std:: cout <<"╭─╯" << std::endl;
}

void Client::stopClient() {
    close(this->sd);
}

void Client::sendMessage(const char* message, std::size_t msg_size) {
    MessageInterface* to_send = new AddRSA(new Message(512), pub_key);
    DEBUG_MSG(std::cout << "created sendMessage message" << std::endl;);
    to_send->addContents((const unsigned char*)message, strlen(message));
    to_send->sendMessage(this->sd);
    delete to_send;
}

std::pair<int,double> Balance(MessageInterface* message, int sd) {
    message->clearContents();
    message->addContents((const unsigned char*)"1",2);    
    message->sendMessage(sd);
    message->clearContents();

    message->receiveMessage(sd);

    std::pair<int,double> balance = {0,0.0};
    memmove(&balance.first,message->getContents(),sizeof(int));
    memmove(&balance.second,message->getContents()+sizeof(int),sizeof(double));

    message->clearContents();
    return balance;
}

void manageBalance(MessageInterface* message, int sd, std::string uname) {
    std::pair<int,double> balance = Balance(message,sd);
    std::cout << "╰─┬──╼ Account information of " << uname << std::endl <<
                 "  ├╼ID      : " << balance.first << std::endl << 
                 "  ├╼balance :" << balance.second << std::endl <<
                 "╭─╯" << std::endl;
}

bool Transfer(MessageInterface* message, std::string recipient, double amount, int sd) {
    message->clearContents();
    message->addContents((const unsigned char*)"2",2);    
    message->sendMessage(sd);
    message->clearContents();
    // send info
    message->addContents((const unsigned char*)&amount,sizeof(double));
    message->addContents((const unsigned char*)recipient.c_str(),recipient.size()+1);
    message->sendMessage(sd);
    message->clearContents();

    message->receiveMessage(sd);
    bool success = false;
    //check for errors
    if (std::string((char *)message->getContents()) == "RECIPIENT_ERROR") {
        std::cerr << "  ╟╼(✖)Recipient is not a client!" << std::endl;
        return false;
    } else if (std::string((char *)message->getContents()) == "NOT_ENOUGH_MONEY") {
        std::cerr << "  ╟╼(✖)Not enoug money in account!" << std::endl;
        return false;
    } else if (std::string((char *)message->getContents()) == "TRANSFER_DONE") {
        success = true;
    }
    message->clearContents();

    return success;
}

void manageTransfer(MessageInterface* message, int sd) {
    std::cout << 
            "╰─┬──╼ Transfering money" << std::endl <<
            "  ├─╼Insert recipient name: " << std::endl << 
            "  ├╼";
    std::string recipient = getStringInputWithMaxSize(message->getReserved());
    double amount = getDoubleInputWithMaxSize(10);
    if (amount <= 0) {
        std::cerr << "  ╟╼(✖)Cannot send no or negative money!" << std::endl <<
                     "╭─╯" << std::endl;
        return;
    }
    bool success = Transfer(message,recipient,amount,sd);
    if (success) {
        std::cout << "  ├╼(✓)Transfer completed correctly!" << std::endl;
    } else {
        std::cerr << "  ╟╼(✖)Error during transfer!" << std::endl;
    }
    std:: cout <<"╭─╯" << std::endl;
}

std::vector<std::tuple<std::string,double,std::string>> 
    History(MessageInterface* message, int sd, std::string uname) {
    message->clearContents();
    message->addContents((const unsigned char*)"3",2);    
    message->sendMessage(sd);
    message->clearContents();

    message->receiveMessage(sd);

    std::vector<std::tuple<std::string,double,std::string>> list_of_transfers;

    int t_amount = 0;
    memmove(&t_amount,message->getContents(),sizeof(int));
    int skip = sizeof(int);
    for (int c = 1; c <= t_amount; c++) {
        double amount = 0;
        std::string timestamp;
        std::string rec_username;
        std::string snd_username;
        
        memmove(&amount,message->getContents()+skip,sizeof(double));
        timestamp = std::string((char*)message->getContents()+skip+sizeof(double));
        rec_username = std::string((char*)message->getContents()+skip+sizeof(double)+20);
        snd_username = std::string((char*)message->getContents()+skip+sizeof(double)+20+rec_username.size()+1);

        skip = sizeof(int) + c*(sizeof(double)+20+rec_username.size()+1+snd_username.size()+1);
        if (snd_username != uname) {
            list_of_transfers.push_back(
                std::tuple<std::string,double,std::string>
                (snd_username,amount,timestamp));
        } else {
            list_of_transfers.push_back(
               std::tuple<std::string,double,std::string>
               (rec_username,-amount,timestamp));
        }
    }

    return list_of_transfers;
}

void manageHistory(MessageInterface* message, int sd, std::string uname) {
    message->clearContents();
    message->addContents((const unsigned char*)"3",2);    
    message->sendMessage(sd);
    message->clearContents();

    message->receiveMessage(sd);

    int t_amount = 0;
    memmove(&t_amount,message->getContents(),sizeof(int));
    bool first = true;

    auto list_of_transfers = History(message,sd,uname);

    std::cout << "╰─┬──╼Transfer History \n";
    for (auto& transaction : list_of_transfers) {
        if (!first) {
            std::cout << "  ╭╯" << std::endl;
        } else {
            first = false;
        }
        std::string t_uname =  std::get<0>(transaction);
        double amount = std::get<1>(transaction);
        std::string timestamp = std::get<2>(transaction);
        if (std::get<1>(transaction) >= 0 ) {
            std::cout <<  "  ╰┬──╼Received " <<
                        "\n   ├╼amount : " << amount << "€" <<
                        "\n   ├╼from   :" << t_uname <<
                        "\n   ├╼on : " << timestamp <<
            std::endl;
        } else {
            std::cout <<  "  ╰┬──╼Sent " <<
                        "\n   ├╼amount :" << -amount <<"€" << 
                        "\n   ├╼to     :" << t_uname <<
                        "\n   ├╼on : " << timestamp <<
            std::endl;
        }
    }
    std::cout << "╭──╯" << std::endl;
}

void Client::clientProcess(std::pair<buffer,buffer> symkeys) {
    MessageInterface* to_send = new AddTimestamp(new AddAES256(new AddMAC(new Message(512), symkeys.second.data()), symkeys.first.data()));
    DEBUG_MSG(std::cout << "created sendMessage message" << std::endl;);
    int choice = 0;
    bool running = true;
    while (running) {
        std::cout << "├──╼Select operation" << std::endl <<
                     "├─╼1: view balance\n" <<
                     "├─╼2: transfer money \n" <<
                     "├─╼3: recent transfers\n" <<
                     "├─╼4: quit" << std::endl <<
                     "├╼";
        choice = getSingleNumberInput();
        switch (choice) {
            case 1:
                manageBalance(to_send,sd, std::string(uname));
                break;
            case 2:
                manageTransfer(to_send,sd);
                break;
            case 3:
                manageHistory(to_send,sd, std::string(uname));
                break;
            case 4:
                to_send->clearContents();
                to_send->addContents((const unsigned char*)"QUIT",5);    
                to_send->sendMessage(sd);
                std::cout << "╰──────╼ Closing client"<<std::endl;
                running = false;
                break;
            default:
                std::cout << "╟╼(✖)Not a valid operation!" << std::endl;
        }
        DEBUG_MSG(std::cout << "Sent message" << std::endl;);
        to_send->clearContents();
    }
    delete to_send;
    //printer.join();
}
