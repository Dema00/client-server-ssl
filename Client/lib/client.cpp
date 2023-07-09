#include "header/client.h"
#include "../../Shared/header/utils.h"

void Client::openConnection() {
    if (connect(this->sd, (struct sockaddr*)&this->addr, sizeof(this->addr)) != 0) {
        std::cerr << "FAILED TO CONNECT" << "\n Is the server running?";
        close(this->sd);
        abort();
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
        std::cerr << "ERROR WHILE OPENING DATABASE";
        close(this->sd);
        abort();
    }

    unsigned char pkey[2000];
    memset(pkey, 0, 2000);
    int k_size = get_user_privkey(db, uname, pkey);
    BIO* private_key_bio = BIO_new_mem_buf(pkey, k_size);
    this->priv_key = PEM_read_bio_PrivateKey(private_key_bio, NULL, 0, NULL);
    BIO_free(private_key_bio);

    std::ifstream input("../Keys/public_server.pem", std::ios::binary);
    std::vector<unsigned char> pubkey_vec(std::istreambuf_iterator<char>(input), {});

    BIO* public_key_bio = BIO_new_mem_buf(pubkey_vec.data(), pubkey_vec.size());
    this->pub_key = PEM_read_bio_PUBKEY(public_key_bio, NULL, 0, NULL);

    if (this->pub_key == NULL) {
        std::cerr << "Error while opening the public RSA key" << std::endl;
        exit(1);
    }
    BIO_free(public_key_bio);
}

void Client::startClient() {
    this->openConnection();

    // Print welcome message
    std::string welcomeFile = "lib/ascii_art.txt";
    std::cout << ReadFile(welcomeFile) << std::endl;

    this->clientLogin();

    buffer symkey = this->symKeyEstablishment();

    this->clientProcess(symkey);
}

buffer Client::symKeyEstablishment() {
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
        std::cerr << "Error: EPHRSA PUBKEY returned NULL\n";
        exit(1);
    }
    ephrsa.clearContents();

    // Certificate verification
    // Verify server cert by loading CA's certificate
    std::string cacert_file_name = "../Keys/CA_cert.pem";
    FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
    if (!cacert_file) {
        std::cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n";
        exit(1);
    }
    DEBUG_MSG(std::cout << "RAW CA CERT: \n" << BIO_dump_fp(stdout, (const char*)cacert_file, 1000) << std::endl;);
    X509* ca_cert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if (!ca_cert) {
        std::cerr << "Error: PEM_read_X509 returned NULL\n";
        exit(1);
    }

    // Load the CRL
    std::string crl_file_name = "../Keys/CA_crl.pem";
    FILE* crl_file = fopen(crl_file_name.c_str(), "r");
    DEBUG_MSG(std::cout << "RAW CA CRL: \n" << BIO_dump_fp(stdout, (const char*)crl_file, 1000) << std::endl;);
    if (!crl_file) {
        std::cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n";
        exit(1);
    }
    X509_CRL* ca_crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if (!ca_crl) {
        std::cerr << "Error: PEM_read_X509_CRL returned NULL\n";
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

    // Verify ERSA pubkey+nonce signature
    unsigned char pubkey_nonce[eph_pubkey_len + 32];
    memmove(pubkey_nonce, eph_pubkey_raw, eph_pubkey_len);
    memmove(pubkey_nonce + eph_pubkey_len, nonce, 32);

    DEBUG_MSG(std::cout << "UNSIGNED PKEY+NONCE: \n" << BIO_dump_fp(stdout, (const char*)pubkey_nonce, 451 + 32) << std::endl;);
    DEBUG_MSG(std::cout << "RECEIVED SIGN: \n" << BIO_dump_fp(stdout, (const char*)ephrsa.getContents(), 256) << std::endl;);

    verify_signature(ephrsa.getContentsMut(), 256, pubkey_nonce, eph_pubkey_len + 32, srv_cert);
    ephrsa.clearContents();

    //Generate and send the symmetric key
    unsigned char symkey[512];
    RAND_bytes(symkey, 32);

    MessageInterface* symkey_send = new AddRSA(new Message(32), ephrsa_pubkey);
    symkey_send->addContents(symkey, 32);
    symkey_send->sendMessage(sd);
    symkey_send->clearContents();
    delete symkey_send;

    // Delete the pubkey
    memset(eph_pubkey_raw, 0, eph_pubkey_len);
    EVP_PKEY_free(ephrsa_pubkey);

    std::vector<unsigned char> symkey_buf;
    symkey_buf.insert(symkey_buf.begin(), symkey, symkey + 32);

    return symkey_buf;
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
        std::cerr << "USERNAME NOT FOUND";
        close(this->sd);
        abort();
    }
    auth.clearContents();

    // Receive nonce for challenge response
    auth.receiveMessage(sd);
    unsigned char nonce[SHA256_DIGEST_LENGTH];
    memcpy(nonce, auth.getContents(), SHA256_DIGEST_LENGTH);

    // Password authentication
    char psw[128];
    while (!login) {
        std::cout << "Insert the password for " << uname << ":" << std::endl;
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
            std::cerr << "Logged in successfully!" << std::endl;
            login = true;
        } else {
            std::cerr << "Wrong password!" << std::endl;
        }
    }
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

void Client::messagePrinter(buffer symkey) {
    MessageInterface* received = new AddTimestamp(new AddAES256(new AddMAC(new Message(512), symkey.data()), symkey.data(), symkey.data()));
    DEBUG_MSG(std::cout << "created msgPrinter message" << std::endl;);

    while (1) {
        received->receiveMessage(this->sd);
        if (received->getStatus() != OK) {
            std::cerr << "Message was not delivered correctly" << std::endl;
            close(this->sd);
            break;
        }
        std::cout << received->getContents() << std::endl;
        received->clearContents();
    }
    delete received;
}

void Client::clientProcess(buffer symkey) {
    std::thread printer(&Client::messagePrinter, this, symkey);
    MessageInterface* to_send = new AddTimestamp(new AddAES256(new AddMAC(new Message(512), symkey.data()), symkey.data(), symkey.data()));
    DEBUG_MSG(std::cout << "created sendMessage message" << std::endl;);
    while (1) {
        char msg[128];
        memset(msg, 0, 128);
        GetInput(msg);
        to_send->addContents((const unsigned char*)msg, 128);
        to_send->sendMessage(this->sd);
        DEBUG_MSG(std::cout << "Sent message" << std::endl;);
        to_send->clearContents();
    }
    delete to_send;
    //printer.join();
}
