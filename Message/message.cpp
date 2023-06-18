#include "header/message.h"

//  %%%%%%%%%%%%%%%%%
//  %    MESSAGE    %
//  %%%%%%%%%%%%%%%%%

Message::Message(std::size_t buf_size): contents(buf_size), reserved_space(buf_size), status(OK) {
    contents.clear();
    contents.reserve(reserved_space);
};

void Message::addContents(const unsigned char* new_contents) {
    buffer::size_type size = strlen((const char*)new_contents);
    contents.insert(contents.end(), new_contents, new_contents+size);

};

void Message::addContentsBeginning(const unsigned char* new_contents) {
    buffer::size_type size = strlen((const char*)new_contents);
    contents.insert(contents.begin(), new_contents, new_contents+size);
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
    return this->reserved_space;
}

void Message::sendMessage(int sd) const {

    if ( send(sd, getContents(), getContentsSize(), 0) == -1) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE SENDING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        abort();
    }
}

void Message::sendMessage(int sd, const unsigned char* contents) const {

    if ( send(sd, contents, strlen((const char*)contents), 0) == -1) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE SENDING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        abort();
    }
}

void Message::receiveMessage(int sd) {
    contents.clear();
    unsigned char recvbuf[reserved_space];
    memset(recvbuf,0,reserved_space);
    int result = recv(sd,(void*)recvbuf,reserved_space,0);
    addContents(recvbuf);
    if ( result == -1 ) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE RECIEVING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        this->status = BROKEN;
        abort();
    } else if (result == 0) {
        this->status = BROKEN;
    }
}

integrity Message::getStatus() const {
    return this->status;
}

buffer* Message::getBuffer() {
    return &this->contents;
}


//  %%%%%%%%%%%%%%%%%
//  %   DECORATOR   %
//  %%%%%%%%%%%%%%%%%

MessageDecorator::MessageDecorator(MessageInterface *message): wrapped_message(message) {}


void MessageDecorator::addContents(const unsigned char* new_contents) {
    this->wrapped_message->addContents(new_contents);
};
void MessageDecorator::addContentsBeginning(const unsigned char* new_contents){
    this->wrapped_message->addContentsBeginning(new_contents);
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
void MessageDecorator::sendMessage(int sd, const unsigned char* contents) const {
    this->wrapped_message->sendMessage(sd, contents);
}
void MessageDecorator::receiveMessage(int sd) {
    this->wrapped_message->receiveMessage(sd);
};


integrity MessageDecorator::getStatus() const {
    return this->wrapped_message->getStatus();
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
//  %    AES 256    %
//  %%%%%%%%%%%%%%%%%

AddAES256::AddAES256(MessageInterface* message, unsigned char* key, unsigned char* iv)
    : MessageDecorator(message), key{key}, iv{iv} {};

void AddAES256::sendMessage(int sd) const {
    unsigned char ciphertext[this->getReserved()];
    memset(ciphertext, 0, getReserved());
    //std::cout<<"msg out plain: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;
    encrypt(wrapped_message->getContentsMut(), getContentsSize()+1, this->key, this->iv, ciphertext);
    //std::cout<<"msg out enc: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;
    this->wrapped_message->sendMessage(sd,ciphertext);
    std::cout << "sent size " << strlen((char *)ciphertext) << std::endl;
    std::cout << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) << std::endl;
}

void AddAES256::receiveMessage(int sd) {
    this->wrapped_message->receiveMessage(sd);
    if (getStatus() == OK){
        this->decryptMessage();
    }
}

void AddAES256::decryptMessage() {
    std::cout<<"msg in: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;
    std::cout << "msg in len: " << this->getContentsSize() << std::endl;
    
    unsigned char plaintext[this->getReserved()];
    memset(plaintext, 0, getReserved());

    size_t plaintext_len = this->getContentsSize();
    std::cout << "cipher len: " << plaintext_len << std::endl;

    decrypt(getContentsMut(), plaintext_len, this->key, this->iv, plaintext);
    this->wrapped_message->clearContents();
    this->wrapped_message->addContents(plaintext);
    this->wrapped_message->getBuffer()->resize(getContentsSize());
    memset(this->wrapped_message->getBuffer()->end().base(),0, strlen((char*)getContents())-getContentsSize() );
    std::cout<<"msg in dec: \n" << BIO_dump_fp (stdout, (const char *)getContents(), getContentsSize()) <<std::endl;
}