#ifndef MESSAGE_H
#define MESSAGE_H
#endif

#include <stdlib.h>

#include <string.h>
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
    BROKEN
};


class MessageInterface {
    public:
        virtual void addContents(const unsigned char* new_contents) = 0;
        virtual void addContentsBeginning(const unsigned char* new_contents) = 0;
        virtual const unsigned char* getContents() const = 0;
        virtual void sendMessage(int sd) const = 0;

        virtual size_t getMsgSize() const = 0;
        virtual integrity getStatus() const = 0;

        virtual ~MessageInterface() {};
};

class Message: public MessageInterface {
    protected:
        unsigned char* contents;
        size_t msg_size;
        integrity status;
    public:
        Message(std::size_t buf_size);
        Message(std::size_t buf_size, int sd);
        void addContents(const unsigned char* new_contents) override;
        void addContentsBeginning(const unsigned char* new_contents) override;
        const unsigned char* getContents() const override;
        void sendMessage(int sd) const override;

        size_t getMsgSize() const override;
        integrity getStatus() const override;

        ~Message() {
            delete[] contents;
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
        void sendMessage(int sd) const override;

        size_t getMsgSize() const override;
        integrity getStatus() const override;

        ~MessageDecorator() {
            delete wrapped_message;
        };
};

class AddAES256: public MessageDecorator {
    protected:
        unsigned const char* key;
    public:
        AddAES256(MessageInterface* message, unsigned const char* key);
        void sendMessage(int sd) const override;
};