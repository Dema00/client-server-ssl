#include "header/message.h"

//  %%%%%%%%%%%%%%%%%
//  %    MESSAGE    %
//  %%%%%%%%%%%%%%%%%

Message::Message(std::size_t buf_size): contents(), reserved_space(buf_size), status(OK) {
    contents.reserve(reserved_space);
    contents.clear();
};

void Message::addContents(const unsigned char* new_contents) {
    buffer::size_type size = strlen((const char*)new_contents);
    contents.insert(contents.end(), new_contents, new_contents+size);

};

void Message::addContentsBeginning(const unsigned char* new_contents) {
    buffer::size_type size = strlen((const char*)new_contents);
    contents.insert(contents.begin(), new_contents, new_contents+size);
}

const unsigned char* Message::getContents() const {
    return contents.data();
};

unsigned char* Message::getContentsMut() {
    return contents.data();
};

size_t Message::getMsgSize() const {
    return contents.size();
}

void Message::sendMessage(int sd) const {
    unsigned char buf[reserved_space];
    memmove(buf,getContents(),getMsgSize());

    if ( send(sd, (void*)buf, getMsgSize(), 0) == -1) {
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
unsigned char* MessageDecorator::getContentsMut() {
    return this->wrapped_message->getContentsMut();
};

void MessageDecorator::sendMessage(int sd) const {
    this->wrapped_message->sendMessage(sd);
};
void MessageDecorator::receiveMessage(int sd) {
    this->wrapped_message->receiveMessage(sd);
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

AddAES256::AddAES256(MessageInterface* message, unsigned char* key): MessageDecorator(message), key{key} {
};

void AddAES256::sendMessage(int sd) const {
    unsigned char plaintext[wrapped_message->getMsgSize()];
    size_t plaintext_len = strlen((char*)this->getContents());
    std::cout << "plain len: " << plaintext_len << std::endl;

    memset(plaintext, 0, wrapped_message->getMsgSize());
    memcpy(plaintext, this->getContents(),plaintext_len);

    encrypt(plaintext, plaintext_len, this->key, NULL, this->wrapped_message->getContentsMut());
    this->wrapped_message->sendMessage(sd);
}

void AddAES256::receiveMessage(int sd) {
    this->wrapped_message->receiveMessage(sd);
    std::cout<<"msg in receive: " << this->getContents() <<std::endl;
    std::cout << "msg in len: " << sizeof((char*)this->getContents()) << std::endl;
    this->decryptMessage();
}

void AddAES256::decryptMessage() {
    std::cout<<"msg in: " << this->getContents() <<std::endl;
    std::cout << "msg in len2: " << sizeof((char*)this->getContents()) << std::endl;
    unsigned char ciphertext[sizeof((char*)this->getContents())];
    size_t ciphertext_len = sizeof((char*)this->getContents());
    std::cout << "cipher len: " << ciphertext_len << std::endl;

    memset(ciphertext, 0, wrapped_message->getMsgSize());
    memmove(ciphertext, this->getContents(),ciphertext_len);

    decrypt(ciphertext, ciphertext_len, reinterpret_cast<unsigned char*>(this->key), NULL, this->wrapped_message->getContentsMut());
}