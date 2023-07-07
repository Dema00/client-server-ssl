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
    BIO* private_key_bio = BIO_new_mem_buf(pkey,2000);
    this->priv_key = PEM_read_bio_PrivateKey(private_key_bio,NULL,0,NULL);
    BIO_free(private_key_bio);

    std::ifstream input( "../Keys/public_server.pem", std::ios::binary );
    std::vector<unsigned char>pubkey_vec (std::istreambuf_iterator<char>(input), {});

    BIO* public_key_bio = BIO_new_mem_buf(pubkey_vec.data(),pubkey_vec.size());
    this->pub_key = PEM_read_bio_PUBKEY(public_key_bio,NULL,0,NULL);
    
    if (this->pub_key == NULL) {
        std::cerr << "Error while opening the public RSA key"<< std::endl;
        exit(1);
    }
    BIO_free(public_key_bio);

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
        std::cout<<"Insert the password for " << uname << ":" <<std::endl;
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
        

    this->clientProcess();
    
}

void Client::stopClient() {
    close(this->sd);
}

void Client::sendMessage(const char* message, std::size_t msg_size) {
    MessageInterface* to_send =  new AddRSA( new Message(512), pub_key);
        DEBUG_MSG(std::cout<<"created sendMessage message" << std::endl;);
    to_send->addContents((const unsigned char*)message, strlen(message));
    to_send->sendMessage(this->sd);
    delete to_send;
}

void Client::messagePrinter() {
    MessageInterface* received = new AddRSA( new Message(512),priv_key);
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
    MessageInterface* to_send =  new AddRSA( new Message(512), pub_key);
        DEBUG_MSG(std::cout<<"created sendMessage message" << std::endl;);
    while(1) {
        char msg [128];
        memset(msg,0,128);
        GetInput(msg);
        to_send->addContents((const unsigned char*)msg,128);
        to_send->sendMessage(this->sd);
        to_send->clearContents();
    }
    delete to_send;
    printer.join();
}