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

Client::Client(const char *hostname, int port, const char* uname, const char* db_path) {
    this->uname = uname;
    this->hostname = hostname;
    this->sd = socket(AF_INET, SOCK_STREAM, 0);
    this->addr = {
        AF_INET, // sin_family
        htons(port) //sin_port
    };
    inet_pton(AF_INET,this->hostname,&(this->addr.sin_addr));

    if (sqlite3_open_v2(db_path,&this->db,SQLITE_OPEN_READWRITE,NULL) != SQLITE_OK) {
        std::cerr<<"ERROR WHILE OPENING DATABASE";
        close(this->sd);
        abort();
    }

    unsigned char pkey [2000];
    memset(pkey,0,2000);
    int k_size = get_user_privkey(db,uname,pkey);
    this->priv_key = std::vector<unsigned char>(k_size);
    priv_key.insert(priv_key.begin(),pkey,pkey+k_size);

    std::ifstream input( "../Keys/public_server.pem", std::ios::binary );

    // copies all data into buffer
    this->pub_key = std::vector<unsigned char>(std::istreambuf_iterator<char>(input), {});
    this->pub_key.shrink_to_fit();


}

void Client::startClient() {
    this->openConnection();

    //assolutamente inutile
    std::string welcomeFile = "lib/ascii_art.txt";
	std::cout<<ReadFile(welcomeFile)<< std::endl;

    bool login = false;

    //sending username
    Message auth(128);
    auth.addContents((const unsigned char*)uname,strlen(uname));
    auth.sendMessage(sd);
    auth.clearContents();
    auth.receiveMessage(sd);
    if (strcmp((const char*)auth.getContents(),"USERNAME_OK") != 0) {
        std::cerr<<"USERNAME NOT FOUND";
        close(this->sd);
        abort();
    }
    auth.clearContents();

    //receive nonce for challenge response
    auth.receiveMessage(sd);
    unsigned char nonce[SHA256_DIGEST_LENGTH];
    memcpy(nonce,auth.getContents(),SHA256_DIGEST_LENGTH);

    //psw auth
    char psw [128];
    while (!login) {
        memset(psw,0,128);
        GetInput(psw);

        unsigned char hashed_psw [SHA256_DIGEST_LENGTH];
        unsigned char hashed_psw_and_nonce [SHA256_DIGEST_LENGTH*2];
        sha256((unsigned char*)psw, strlen(psw), hashed_psw);
        memmove(hashed_psw_and_nonce,hashed_psw,SHA256_DIGEST_LENGTH);
        memmove(hashed_psw_and_nonce+SHA256_DIGEST_LENGTH,hashed_psw,SHA256_DIGEST_LENGTH);
        sha256(hashed_psw_and_nonce,SHA256_DIGEST_LENGTH*2,hashed_psw);
        auth.clearContents();
        auth.addContents(hashed_psw,SHA256_DIGEST_LENGTH);
        auth.sendMessage(sd);
        auth.clearContents();
        auth.receiveMessage(sd);
        if (strcmp((const char*)auth.getContents(),"PASSWORD_OK") == 0) {
            std::cerr<<"Logged in succesfully!"<<std::endl;
            login = true;
            
        } else {
            std::cerr<<"Wrong password!"<<std::endl;
        }

    }

    //send nonce for ephemeral key exchange
    auth.clearContents();
    memset(nonce,0,SHA256_DIGEST_LENGTH);
    RAND_bytes(nonce, SHA256_DIGEST_LENGTH);
    auth.addContents(nonce, SHA256_DIGEST_LENGTH);
    auth.sendMessage(sd);
    auth.clearContents();
        DEBUG_MSG(std::cout<<"sen nonce" << std::endl;);

    Message ephrsa(2048);
    //receive ERSA pubkey
    ephrsa.receiveMessage(sd);
    BIO* eph_pub_key_bio = BIO_new_mem_buf(ephrsa.getContents(),ephrsa.getContentsSize());
    EVP_PKEY* ehprsa_pubkey = PEM_read_bio_PUBKEY(eph_pub_key_bio,NULL,0,NULL);
    BIO_free(eph_pub_key_bio);
    ephrsa.clearContents();

    //verify server cert
    // load the CA's certificate:
    std::string cacert_file_name="../Keys/CA_cert.pem";
    FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
    if(!cacert_file){ std::cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; exit(1); }
        DEBUG_MSG(std::cout<<"RAW CA CERT: \n" << BIO_dump_fp (stdout, (const char*)cacert_file,1000 ) <<std::endl;);
    X509* ca_cert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if(!ca_cert){ std::cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }

    // load the CRL:
    std::string crl_file_name="../Keys/CA_crl.pem";
    FILE* crl_file = fopen(crl_file_name.c_str(), "r");
        DEBUG_MSG(std::cout<<"RAW CA CRL: \n" << BIO_dump_fp (stdout, (const char*)crl_file,1000 ) <<std::endl;);
    if(!crl_file){ std::cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n"; exit(1); }
    X509_CRL* ca_crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!ca_crl){ std::cerr << "Error: PEM_read_X509_CRL returned NULL\n"; exit(1); }

    //receive srv_cert
    ephrsa.receiveMessage(sd);
    BIO* srv_cert_bio = BIO_new_mem_buf(ephrsa.getContents(),ephrsa.getContentsSize());
    X509* srv_cert = PEM_read_bio_X509(srv_cert_bio,NULL,0,NULL);
    BIO_free(srv_cert_bio);
    ephrsa.clearContents();

    verify_cert(ca_cert,ca_crl,srv_cert);


    //verify ERSA pubkey+nonce singature

    //generate and send symmetric key

    //delete pubkey
        

    this->clientProcess();
    
}

void Client::stopClient() {
    close(this->sd);
}

void Client::sendMessage(const char* message, std::size_t msg_size) {
    MessageInterface* to_send =  new AddRSA( new Message(512), pub_key.data());
        DEBUG_MSG(std::cout<<"created sendMessage message" << std::endl;);
    to_send->addContents((const unsigned char*)message, strlen(message));
    to_send->sendMessage(this->sd);
    delete to_send;
}

void Client::messagePrinter() {
    MessageInterface* received = new AddRSA( new Message(512),priv_key.data());
        DEBUG_MSG(std::cout<<"created msgPrinter message" << std::endl;);

    while(1) {
        received->receiveMessage(this->sd);
        if( received->getStatus() != OK) {
            close(this->sd);
            break;
        }
        std::cout << received->getContents() << std::endl;
        received->clearContents();
    }
    delete received;
}

void Client::clientProcess() {
    std::thread printer(&Client::messagePrinter, this);
    while(1) {
        char msg [128];
        GetInput(msg);
        this->sendMessage(msg, 128);
    }
    printer.join();
}