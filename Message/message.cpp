#include "header/message.h"

//  %%%%%%%%%%%%%%%%%
//  %    MESSAGE    %
//  %%%%%%%%%%%%%%%%%

Message::Message(std::size_t buf_size) {
    this->contents = new unsigned char[buf_size];
    this->msg_size = buf_size;
    this->status = OK;
    memset(this->contents, 0, buf_size);
};

Message::Message(std::size_t buf_size, int sd) {
    this->contents = new unsigned char[buf_size];
    this->msg_size = buf_size;
    this->status = OK;
    memset(this->contents, 0, buf_size);

    int result = recv(sd,(void*)this->contents,buf_size,0);
    if ( result == -1 ) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE RECIEVING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        this->status = BROKEN;
        abort();
    } else if (result == 0) {
        this->status = BROKEN;
    }
};

void Message::addContents(const unsigned char* new_contents) {
    //should be equivalent to stract but with raw bytes
    //not sure
    memcpy(this->contents + strlen((const char*)this->contents), new_contents, strlen((const char*)new_contents));
};

void Message::addContentsBeginning(const unsigned char* new_contents) {
    unsigned char temp[this->msg_size];
    memset(temp, 0, this->msg_size);

    memcpy(temp,this->contents, strlen((const char *)this->contents));

    memset(this->contents, 0, this->msg_size);
    memcpy(this->contents, new_contents, strlen((const char *)new_contents));
    memcpy(this->contents + strlen((const char*)this->contents), temp, strlen((const char*)temp));
}

const unsigned char* Message::getContents() const {
    return this->contents;
};

size_t Message::getMsgSize() const {
    return this->msg_size;
}

void Message::sendMessage(int sd) const {
    if ( send(sd, (void*)this->contents, strlen((const char *)this->contents), 0) == -1) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE SENDING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        abort();
    }
}

integrity Message::getStatus() const {
    return this->status;
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
const unsigned char* MessageDecorator::getContents() const {
    return this->wrapped_message->getContents();
};
void MessageDecorator::sendMessage(int sd) const {
    this->wrapped_message->sendMessage(sd);
};
integrity MessageDecorator::getStatus() const {
    return this->wrapped_message->getStatus();
}

size_t MessageDecorator::getMsgSize() const {
    return this->wrapped_message->getMsgSize();
}

//  %%%%%%%%%%%%%%%%%
//  %    AES 256    %
//  %%%%%%%%%%%%%%%%%

AddAES256::AddAES256(MessageInterface* message, unsigned const char* key): MessageDecorator(message), key{key} {};

void AddAES256::sendMessage(int sd) const {
    unsigned char plaintext[wrapped_message->getMsgSize()];
    memset(plaintext, 0, wrapped_message->getMsgSize());
}