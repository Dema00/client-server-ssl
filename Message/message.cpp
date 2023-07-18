#include "header/message.h"


std::vector<std::string> MsgError = {
    "Ok",
    "Timestamps not matching",
    "MAC digests not matching",
    "Message is empty",
    "Error during TCP reception",
};

//  %%%%%%%%%%%%%%%%%
//  %    MESSAGE    %-----------------------------------------------------------------------
//  %%%%%%%%%%%%%%%%%

Message::Message(std::size_t buf_size): contents(buf_size), status(OK) {
    contents.clear();
    contents.reserve(buf_size);
};

void Message::addContents(const unsigned char* new_contents, int len) {
    contents.insert(contents.end(), new_contents, new_contents+len);

};

void Message::addContentsBeginning(const unsigned char* new_contents, int len) {
    contents.insert(contents.begin(), new_contents, new_contents+len);
}

void Message::clearContents() {
    contents.clear();
}

const unsigned char* Message::getContents() const {
    return contents.data();
};

unsigned char* Message::getContentsMut() {
    return contents.data();
};

size_t Message::getContentsSize() const {
    return contents.size();
}

size_t Message::getReserved() const {
    return contents.capacity();
}

void Message::sendMessage(int sd) {

    if ( send(sd, getContents(), getContentsSize(), 0) == -1) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE SENDING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        abort();
    }
}

void Message::sendMessage(int sd, const unsigned char* contents, int len) {

    if ( send(sd, contents, len, 0) == -1) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE SENDING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        abort();
    }
}

void Message::receiveMessage(int sd) {
    contents.clear();
    unsigned char recvbuf[getReserved()];

        DEBUG_MSG(std::cout << "reserved: " <<getReserved() << std::endl;);

    memset(recvbuf,0,getReserved());
    int result = recv(sd,(void*)recvbuf,getReserved(),0);
    addContents(recvbuf, this->getReserved());
    if ( result == -1 ) {
            DEBUG_MSG(std::cout <<"RECIEVING FROM  : " << sd << std::endl;);
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE RECIEVING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        this->status = RECV_ERROR;
        abort();
    } else if (result == 0) {
        this->status = EMPTY;
    }
        DEBUG_MSG(std::cout<<"msg in: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;);
    finalizeReception();
}

void Message::finalizeReception() {};

integrity Message::getStatus() const {
    return this->status;
}

void Message::setStatus(integrity new_status) {
    this->status = new_status;
}

buffer* Message::getBuffer() {
    return &this->contents;
}


//  %%%%%%%%%%%%%%%%%
//  %   DECORATOR   %-----------------------------------------------------------------------
//  %%%%%%%%%%%%%%%%%

MessageDecorator::MessageDecorator(MessageInterface *message): wrapped_message(message) {}


void MessageDecorator::addContents(const unsigned char* new_contents, int len) {
    this->wrapped_message->addContents(new_contents, len);
};
void MessageDecorator::addContentsBeginning(const unsigned char* new_contents, int len){
    this->wrapped_message->addContentsBeginning(new_contents, len);
}
void MessageDecorator::clearContents() {
    this->wrapped_message->clearContents();
}

const unsigned char* MessageDecorator::getContents() const {
    return this->wrapped_message->getContents();
};
unsigned char* MessageDecorator::getContentsMut() {
    return this->wrapped_message->getContentsMut();
};

void MessageDecorator::sendMessage(int sd) {
    this->wrapped_message->sendMessage(sd);
};
void MessageDecorator::sendMessage(int sd, const unsigned char* contents, int len) {
    this->wrapped_message->sendMessage(sd, contents, len);
}
void MessageDecorator::receiveMessage(int sd) {
    this->wrapped_message->receiveMessage(sd);
};

void MessageDecorator::finalizeReception() {
    this->wrapped_message->finalizeReception();
};

integrity MessageDecorator::getStatus() const {
    return this->wrapped_message->getStatus();
}

void MessageDecorator::setStatus(integrity new_status) {
    return this->wrapped_message->setStatus(new_status);
}

size_t MessageDecorator::getReserved() const {
    return this->wrapped_message->getReserved();
}

size_t MessageDecorator::getContentsSize() const {
    return this->wrapped_message->getContentsSize();
}

buffer* MessageDecorator::getBuffer() {
    return this->wrapped_message->getBuffer();
}

//  %%%%%%%%%%%%%%%%%
//  %    AES RSA    %-----------------------------------------------------------------------
//  %%%%%%%%%%%%%%%%%

void print_EVP_PubKEY(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1) {
        char* buffer;
        long keySize = BIO_get_mem_data(bio, &buffer);
        std::cout << "RSA KEY:\n" << std::string(buffer, keySize) << std::endl;
    }
    else {
        std::cerr << "Error while writing the RSA key" << std::endl;
    }
    BIO_free(bio);
}


AddRSA::AddRSA(MessageInterface* message, EVP_PKEY* msg_key): MessageDecorator(message){

    this->key = msg_key;

    if (this->key == NULL) {
        std::cerr << "Error while opening the RSA key"<< std::endl;
    }

        //DEBUG_MSG(print_EVP_PrivKEY(msg_key););
        //DEBUG_MSG(print_EVP_PubKEY(msg_key););
};

void AddRSA::sendMessage(int sd) {
        DEBUG_MSG(std::cout<<"------- begin RSA send messagge -------" << std::endl;);
    unsigned char ciphertext[this->getReserved()];
    memset(ciphertext, 0, getReserved());

    unsigned char plaintext[this->getReserved()];
    memset(plaintext, 0, getReserved());
    memmove(plaintext,wrapped_message->getContents(),getReserved());
        DEBUG_MSG(std::cout<<"RSA PLAINTEXT: \n" << BIO_dump_fp (stdout, (const char *)plaintext, getContentsSize()) <<std::endl;);

    // allocate buffers for encrypted key and IV:
    unsigned char* encrypted_key = (unsigned char*)malloc(EVP_PKEY_size(key));
    unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_256_xts()));
    if(!encrypted_key || !iv) { std::cerr << "Error: malloc returned NULL (encrypted key too big?)\n"; exit(1); }

        DEBUG_MSG(std::cout<<"Succesfully allocated enc_key and iv" << std::endl;);

    int len = rsa_encrypt(&key, plaintext, wrapped_message->getContentsSize(), encrypted_key, EVP_PKEY_size(key), iv, ciphertext);
    char len_str [5];
    sprintf(len_str, "%03d", len);

        DEBUG_MSG(std::cout<<"Succesfully encrypted RSA msg" << std::endl;);
        DEBUG_MSG(std::cout<<"RSA msg Size" << this->getReserved() <<std::endl;);
        DEBUG_MSG(std::cout<<"IV: \n" << BIO_dump_fp (stdout, (const char *)iv, EVP_CIPHER_iv_length(EVP_aes_256_xts())) <<std::endl;);
        DEBUG_MSG(std::cout<<"Enc_key: \n" << BIO_dump_fp (stdout, (const char *)encrypted_key, EVP_PKEY_size(key)) <<std::endl;);
        DEBUG_MSG(std::cout<<"RSA CIPHERTEXT: \n" << BIO_dump_fp (stdout, (const char *)ciphertext, len) <<std::endl;);

    wrapped_message->clearContents();
    wrapped_message->addContents(iv,EVP_CIPHER_iv_length(EVP_aes_256_xts()));
    wrapped_message->addContents(encrypted_key,EVP_PKEY_size(key));
    wrapped_message->addContents((unsigned char*)len_str, strlen(len_str));
    wrapped_message->addContents(ciphertext, len);
        DEBUG_MSG(std::cout<<"msg out rsa: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;);
    wrapped_message->sendMessage(sd);

    free(encrypted_key);
    free(iv);
}

void AddRSA::receiveMessage(int sd) {
    wrapped_message->receiveMessage(sd);
    finalizeReception();
}

void AddRSA::finalizeReception() {
    if (getStatus() == OK){
        this->decryptMessage();
    } else {
        std::cerr << MsgError[getStatus()] << std::endl;
    }
}

void AddRSA::decryptMessage() {
        DEBUG_MSG(std::cout<<"------- begin RSA decrypt messagge -------" << std::endl;);
    unsigned char plaintext[this->getReserved()];
    memset(plaintext, 0, getReserved());

    unsigned char ciphertext[this->getReserved()];
    memset(ciphertext, 0, getReserved());

    unsigned char iv[EVP_CIPHER_iv_length(EVP_aes_256_xts())];
    memset(iv, 0, EVP_CIPHER_iv_length(EVP_aes_256_xts()));

    unsigned char encrypted_key[EVP_PKEY_size(key)];
    memset(iv, 0, EVP_PKEY_size(key));

    unsigned char len_str [3];
    int cipher_len;

    DEBUG_MSG(std::cout<<"msg in rsa cipher: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()+1) <<std::endl;);


    int iv_size = EVP_CIPHER_iv_length(EVP_aes_256_xts());
    int ekey_size = EVP_PKEY_size(key);

    memmove(iv,wrapped_message->getContents(), iv_size);
    memmove(encrypted_key, wrapped_message->getContents()+iv_size, ekey_size);
    memmove(len_str, wrapped_message->getContents()+iv_size+ekey_size, 3);
    cipher_len = atoi((char*)len_str);
    memmove(ciphertext,wrapped_message->getContents() +iv_size +ekey_size+3,cipher_len);

        DEBUG_MSG(std::cout<<"IV: \n" << BIO_dump_fp (stdout, (const char *)iv, iv_size) <<std::endl;);
        DEBUG_MSG(std::cout<<"Enc_key: \n" << BIO_dump_fp (stdout, (const char *)encrypted_key, ekey_size) <<std::endl;);
        DEBUG_MSG(std::cout<<"Plaintext len: \n" << cipher_len <<std::endl;);
        DEBUG_MSG(std::cout<<"Plaintext: \n" << BIO_dump_fp (stdout, (const char *)ciphertext, cipher_len) <<std::endl;);

    int len = rsa_decrypt(key, ciphertext,cipher_len,encrypted_key,ekey_size,iv,plaintext);
    
    wrapped_message->clearContents();
    wrapped_message->addContents(plaintext,len);
        DEBUG_MSG(std::cout<<"normal output of rsa dec" << (const char *)getContents() << std::endl;);
        DEBUG_MSG(std::cout<<"msg in rsa clean: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()+1) <<std::endl;);
}

//  %%%%%%%%%%%%%%%%%
//  %    AES 256    %-----------------------------------------------------------------------
//  %%%%%%%%%%%%%%%%%

AddAES256::AddAES256(MessageInterface* message, unsigned char* key)
    : MessageDecorator(message), key{key} {};

void AddAES256::sendMessage(int sd) {
    unsigned char ciphertext[this->getReserved()];
    memset(ciphertext, 0, getReserved());
        DEBUG_MSG(std::cout<<"msg out before int: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;);
    int plaintext_len = wrapped_message->getContentsSize();
    wrapped_message->addContentsBeginning((unsigned char *)&plaintext_len,sizeof(int));
        DEBUG_MSG(std::cout<<"msg out after int: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;);

    unsigned char msg_iv[64];
    RAND_bytes(msg_iv,64);
    int len = encrypt(wrapped_message->getContentsMut(), wrapped_message->getReserved(), this->key, msg_iv, ciphertext);
    wrapped_message->clearContents();
    //resizing for IV
    wrapped_message->getBuffer()->reserve(wrapped_message->getReserved()+64);
    wrapped_message->addContents(msg_iv,64);
    wrapped_message->addContents(ciphertext, len);
        DEBUG_MSG(std::cout<<"msg out enc: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;);
    this->wrapped_message->sendMessage(sd);
    getBuffer()->resize(getReserved()-64);
}

void AddAES256::receiveMessage(int sd) {
    //resizing for IV
    getBuffer()->reserve(getReserved()+64);
    wrapped_message->receiveMessage(sd);
    finalizeReception();
}

void AddAES256::finalizeReception() {
    if (getStatus() == OK){
        this->decryptMessage();
    } else {
        std::cerr << MsgError[getStatus()] << std::endl;
    }
}

void AddAES256::decryptMessage() {
    
    unsigned char plaintext[this->getReserved()];
    memset(plaintext, 0, getReserved());

    unsigned char msg_iv [64];
    memmove(msg_iv,getContents(),64);

    decrypt(getContentsMut()+64, getContentsSize(), this->key, msg_iv, plaintext);

    int plaintext_len = 0;
    memcpy((unsigned char*)&plaintext_len,plaintext,sizeof(int));
        DEBUG_MSG(std::cout << "pl len " << plaintext_len << std::endl;);

        DEBUG_MSG(std::cout<<"msg in dec: \n" << BIO_dump_fp (stdout, (const char *)plaintext, getReserved()) <<std::endl;);
    getBuffer()->resize(getReserved()-64);
    this->wrapped_message->clearContents();
    this->wrapped_message->addContents((unsigned char*)plaintext+sizeof(int), plaintext_len);
    //this->wrapped_message->getBuffer()->resize(strlen((const char*)wrapped_message->getContents()));
    //wrapped_message->getBuffer()->shrink_to_fit();
    //memset(this->wrapped_message->getBuffer()->end().base(),0, getReserved()-getContentsSize() );
        DEBUG_MSG(std::cout<<"msg in clean: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;);
}

//  %%%%%%%%%%%%%%%%%
//  %      MAC      %-----------------------------------------------------------------------
//  %%%%%%%%%%%%%%%%%

AddMAC::AddMAC(MessageInterface* message, unsigned char* key): MessageDecorator(message), key{key} {
};

void AddMAC::sendMessage(int sd) {
    unsigned char digest[32];
    unsigned int len = 32;
    hmac(key,32,getContents(),getContentsSize(),digest, &len);
    wrapped_message->getBuffer()->reserve(getReserved()+32);

    wrapped_message->addContentsBeginning(digest, 32);
        DEBUG_MSG(std::cout<<"msg out MAC: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getReserved()) <<std::endl;);
        DEBUG_MSG(std::cout<<"MAC Digest: \n" << BIO_dump_fp (stdout, (const char *)digest, 32) <<std::endl;);
    wrapped_message->sendMessage(sd);
    wrapped_message->getBuffer()->resize(getReserved()-32);
    wrapped_message->getBuffer()->shrink_to_fit();
        DEBUG_MSG(std::cout<<"Reserved after resizing : "<<getReserved() << std::endl;);
}

void AddMAC::receiveMessage(int sd) {
    getBuffer()->reserve(getReserved()+32);
    wrapped_message->receiveMessage(sd);
    finalizeReception();
    getBuffer()->resize(getReserved()-32);
    getBuffer()->shrink_to_fit();
}

void AddMAC::finalizeReception() {
    unsigned char received_digest[32];
    unsigned char local_digest[32];
    memset(local_digest,0,32);

    memmove(received_digest,getContents(),32);
    memmove(getContentsMut(),getContents()+32,getReserved()-32);

        DEBUG_MSG(std::cout<<"msg IN MAC: \n" << BIO_dump_fp (stdout, (const char *)received_digest, 32) <<std::endl;);
    unsigned int len = 32;
    hmac(key,32,getContents(),getContentsSize()-32,local_digest, &len);
        DEBUG_MSG(std::cout<<"msg LOCAL MAC: \n" << BIO_dump_fp (stdout, (const char *)local_digest, 32) <<std::endl;);

    if( memcmp(received_digest, local_digest, 32) != 0 ) {
        setStatus(WRONG_MAC);
    }

}

//  %%%%%%%%%%%%%%%%%
//  %   TIMESTAMP   %-----------------------------------------------------------------------
//  %%%%%%%%%%%%%%%%%

AddTimestamp::AddTimestamp(MessageInterface* message): MessageDecorator(message) {
};

void AddTimestamp::sendMessage(int sd) {
        DEBUG_MSG(std::cout << "added timestamp " << std::endl;);
    std::time_t now = std::time(0);
    std::tm * ptm = std::localtime(&now);
    char buffer[19];
    // Format: Mo, 15.06.2009 20:20:00
    std::strftime(buffer, 19, "%d.%m.%Y%H:%M:%S", ptm);  
    wrapped_message->addContentsBeginning((unsigned char*)buffer,18);
        DEBUG_MSG(std::cout<<"msg out time: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;);
    wrapped_message->sendMessage(sd);
}

void AddTimestamp::receiveMessage(int sd) {
    wrapped_message->receiveMessage(sd);
    finalizeReception();
}

void AddTimestamp::finalizeReception() {
    unsigned char timestamp[18];
    memmove(timestamp,getContents(),18);
    memmove(getContentsMut(),getContents()+18,getReserved()-18);
    wrapped_message->getBuffer()->resize(getContentsSize()-18);
    DEBUG_MSG(std::cout<<"msg in time: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;);
    //getBuffer()->resize(getReserved()-18);
    //DEBUG_MSG(std::cout<<getReserved()<< " reserved after timestamp " << std::endl;);
    //wrapped_message->getBuffer()->shrink_to_fit();

    std::time_t now = std::time(0);
    std::tm * ptm = std::localtime(&now);
    char local_timestamp[18];
    // Format: Mo, 15.06.2009 20:20:00
    std::strftime(local_timestamp, 19, "%d.%m.%Y%H:%M:%S", ptm);  
    if (memcmp(timestamp,(unsigned char*)local_timestamp,18) != 0) {
        setStatus(WRONG_TIMESTAMP);
    }
}