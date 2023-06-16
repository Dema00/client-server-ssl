#ifndef MESSAGE_H
#define MESSAGE_H
#endif

#include "../../Shared/header/security.h"

#include <stdlib.h>

#include <string.h>
#include <vector>
#include <iostream>

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum integrity {
    OK,
    BROKEN,
};

typedef std::vector<unsigned char> buffer;


class MessageInterface {
    public:
        virtual void addContents(const unsigned char* new_contents) = 0;
        virtual void addContentsBeginning(const unsigned char* new_contents) = 0;

        virtual const unsigned char* getContents() const = 0;
        virtual unsigned char* getContentsMut() = 0;

        virtual void sendMessage(int sd) const = 0;
        virtual void receiveMessage(int sd) = 0;

        virtual size_t getMsgSize() const = 0;
        virtual integrity getStatus() const = 0;

        virtual ~MessageInterface() {};
};

class Message: public MessageInterface {
    protected:
        buffer contents;
        size_t reserved_space;
        integrity status;
    public:
        Message(std::size_t buf_size);

        void addContents(const unsigned char* new_contents) override;
        void addContentsBeginning(const unsigned char* new_contents) override;

        const unsigned char* getContents() const override;
        unsigned char* getContentsMut() override;

        void sendMessage(int sd) const override;
        void receiveMessage(int sd) override;

        size_t getMsgSize() const override;
        integrity getStatus() const override;

        ~Message() {
            memset(contents.data(),0,contents.size());
            contents.clear();
        };
};

class MessageDecorator: public MessageInterface {
    protected:
        MessageInterface* wrapped_message;
    
    public:
        MessageDecorator(MessageInterface *message);
        void addContents(const unsigned char* new_contents) override;

        void addContentsBeginning(const unsigned char* new_contents) override;
        const unsigned char* getContents() const override;

        unsigned char* getContentsMut() override;

        void sendMessage(int sd) const override;
        void receiveMessage(int sd) override;

        size_t getMsgSize() const override;
        integrity getStatus() const override;

        ~MessageDecorator() {
            delete wrapped_message;
        };
};

class AddAES256: public MessageDecorator {
    protected:
        unsigned char* key;
    public:
        AddAES256(MessageInterface* message, unsigned char* key);
        void decryptMessage();
        void sendMessage(int sd) const override;
        void receiveMessage(int sd) override;
};