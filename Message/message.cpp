#include "header/message.h"

//  %%%%%%%%%%%%%%%%%
//  %    MESSAGE    %
//  %%%%%%%%%%%%%%%%%

Message::Message(std::size_t buf_size) {
    this->contents = new char[buf_size];
    memset(this->contents, 0, buf_size);
};

Message::Message(std::size_t buf_size, int sd) {
    this->contents = new char[buf_size];
    memset(this->contents, 0, buf_size);
    if ( recv(sd,(void*)this->contents,buf_size,0) == -1) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE SENDING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
    }
};

void Message::addContents(const char* new_contents) {
    strcat(this->contents, new_contents);
};

const char* Message::getContents() const {
    return this->contents;
};

void Message::sendMessage(int sd) const {
    if ( send(sd, (void*)this->contents, strlen(this->contents), 0) == -1) {
        char buffer[ 256 ];
        char * errorMsg = strerror_r( errno, buffer, 256 ); // GNU-specific version, Linux default
        printf("ERROR WHILE SENDING MESSAGE: %s \n", errorMsg); //return value has to be used since buffer might not be modified
        abort();
    }
}


//  %%%%%%%%%%%%%%%%%
//  %   DECORATOR   %
//  %%%%%%%%%%%%%%%%%

MessageDecorator::MessageDecorator(Message *message) {
    this->wrapped_message = message;
}


void MessageDecorator::addContents(const char* new_contents) {
    this->wrapped_message->addContents(new_contents);
};
const char* MessageDecorator::getContents() const {
    this->wrapped_message->getContents();
};
void MessageDecorator::sendMessage(int sd) const {
    this->wrapped_message->sendMessage(sd);
};