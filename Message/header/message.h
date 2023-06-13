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


class MessageInterface {
    public:
        virtual void addContents(const char* new_contents) = 0;
        virtual const char* getContents() const = 0;
        virtual void sendMessage(int sd) const = 0;
        virtual ~MessageInterface() {};
};

class Message: public MessageInterface {
    protected:
        char* contents;
    public:
        Message(std::size_t buf_size);
        Message(std::size_t buf_size, int sd);
        void addContents(const char* new_contents) override;
        const char* getContents() const override;
        void sendMessage(int sd) const override;
        ~Message() {
            delete[] contents;
        };
};

class MessageDecorator: public MessageInterface {
    protected:
        MessageInterface* wrapped_message;
    
    public:
        MessageDecorator(Message *message);
        void addContents(const char* new_contents) override;
        const char* getContents() const override;
        void sendMessage(int sd) const override;
        ~MessageDecorator() {
            delete wrapped_message;
        };
};