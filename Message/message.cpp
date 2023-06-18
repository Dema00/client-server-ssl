#include "header/message.h"

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

void Message::sendMessage(int sd) const {

    if ( send(sd, getContents(), getContentsSize(), 0) == -1) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE SENDING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        abort();
    }
}

void Message::sendMessage(int sd, const unsigned char* contents, int len) const {

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
    memset(recvbuf,0,getReserved());
    int result = recv(sd,(void*)recvbuf,getReserved(),0);
    addContents(recvbuf, this->getReserved());
    if ( result == -1 ) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE RECIEVING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        this->status = RECV_ERROR;
        abort();
    } else if (result == 0) {
        this->status = EMPTY;
    }
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

void MessageDecorator::sendMessage(int sd) const {
    this->wrapped_message->sendMessage(sd);
};
void MessageDecorator::sendMessage(int sd, const unsigned char* contents, int len) const {
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
//  %    AES 256    %-----------------------------------------------------------------------
//  %%%%%%%%%%%%%%%%%

AddAES256::AddAES256(MessageInterface* message, unsigned char* key, unsigned char* iv)
    : MessageDecorator(message), key{key}, iv{iv} {};

void AddAES256::sendMessage(int sd) const {
    unsigned char ciphertext[this->getReserved()];
    memset(ciphertext, 0, getReserved());
    //std::cout<<"msg out plain: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;
    int len = encrypt(wrapped_message->getContentsMut(), wrapped_message->getReserved()-16, this->key, this->iv, ciphertext);
    //std::cout<<"msg out enc: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;
    this->wrapped_message->sendMessage(sd,ciphertext, len);
    std::cout << "sent size " << len << std::endl;
    std::cout << BIO_dump_fp (stdout, (const char *)ciphertext, len) << std::endl;
}

void AddAES256::receiveMessage(int sd) {
    wrapped_message->receiveMessage(sd);
    finalizeReception();
}

void AddAES256::finalizeReception() {
    if (getStatus() == OK){
        this->decryptMessage();
    }
    wrapped_message->finalizeReception();
}

void AddAES256::decryptMessage() {
    std::cout<<"msg in: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;
    std::cout << "msg in len: " << this->getContentsSize() << std::endl;
    
    unsigned char plaintext[this->getReserved()];
    memset(plaintext, 0, getReserved());

    size_t plaintext_len = this->getContentsSize();
    std::cout << "cipher len: " << plaintext_len << std::endl;

    int len = decrypt(getContentsMut(), plaintext_len, this->key, this->iv, plaintext);
    std::cout << "ziocan" << std::endl;
    this->wrapped_message->clearContents();
    this->wrapped_message->addContents(plaintext, len);
    std::cout<<"msg in dec: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;
    this->wrapped_message->getBuffer()->resize(strlen((const char*)wrapped_message->getContents()));
    //memset(this->wrapped_message->getBuffer()->end().base(),0, strlen((char*)getContents())-getContentsSize() );
    std::cout<<"msg in clean: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;
}

//  %%%%%%%%%%%%%%%%%
//  %      MAC      %-----------------------------------------------------------------------
//  %%%%%%%%%%%%%%%%%

AddMAC::AddMAC(MessageInterface* message): MessageDecorator(message) {
    this->getBuffer()->reserve(getReserved()+256);
};

void AddMAC::sendMessage(int sd) const {
    unsigned char digest[getReserved()];
    int len = hmac(key,32,getContents(),getReserved(),digest);
    wrapped_message->addContentsBeginning(digest, len);
    this->sendMessage(sd);
}

void AddMAC::receiveMessage(int sd) {
    wrapped_message->receiveMessage(sd);
    finalizeReception();
}

void AddMAC::finalizeReception() {
    unsigned char received_digest[256];
    unsigned char local_digest[getReserved()];

    memmove(received_digest,getContents(),256);
    memmove(getContentsMut(),getContents()+256,getReserved()-256);
    getBuffer()->resize(getReserved()-256);

    int len = hmac(key,32,getContents(),getReserved(),local_digest);

    if( memcmp(received_digest, local_digest, 256) != 0 ) {
        setStatus(WRONG_MAC);
    }

}

//  %%%%%%%%%%%%%%%%%
//  %   TIMESTAMP   %-----------------------------------------------------------------------
//  %%%%%%%%%%%%%%%%%

AddTimestamp::AddTimestamp(MessageInterface* message): MessageDecorator(message) {
};

void AddTimestamp::sendMessage(int sd) const {
    std::time_t now = std::time(0);
    std::tm * ptm = std::localtime(&now);
    char buffer[19];
    // Format: Mo, 15.06.2009 20:20:00
    std::strftime(buffer, 19, "%d.%m.%Y%H:%M:%S", ptm);  
    wrapped_message->addContentsBeginning((unsigned char*)buffer,19);
    wrapped_message->sendMessage(sd);
}

void AddTimestamp::receiveMessage(int sd) {
    wrapped_message->receiveMessage(sd);
    finalizeReception();
}

void AddTimestamp::finalizeReception() {
    unsigned char timestamp[19];
    memmove(timestamp,getContents(),19);
    memmove(getContentsMut(),getContents()+19,getReserved()-19);
    getBuffer()->resize(getReserved()-19);
    struct tm tm;
    strptime((char *)timestamp, "%d.%m.%Y%H:%M:%S", &tm);
    time_t t = mktime(&tm);
    if (t != std::time(0)) {
        setStatus(WRONG_TIMESTAMP);
    }
}