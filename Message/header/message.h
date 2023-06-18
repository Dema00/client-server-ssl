#ifndef MESSAGE_H
#define MESSAGE_H
#endif

#include "../../Shared/header/crypto.h"

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

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

enum integrity {
    OK,
    BROKEN,
};

typedef std::vector<unsigned char> buffer;


class MessageInterface {
    public:
        virtual void addContents(const unsigned char* new_contents) = 0;
        virtual void addContentsBeginning(const unsigned char* new_contents) = 0;
        virtual void clearContents() = 0;

        virtual const unsigned char* getContents() const = 0;
        virtual unsigned char* getContentsMut() = 0;

        virtual void sendMessage(int sd) const = 0;
        virtual void sendMessage(int sd, const unsigned char* contents) const = 0;
        virtual void receiveMessage(int sd) = 0;

        virtual size_t getContentsSize() const = 0;
        virtual size_t getReserved() const = 0;
        virtual integrity getStatus() const = 0;

        virtual buffer* getBuffer() = 0;

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
        void clearContents() override;

        const unsigned char* getContents() const override;
        unsigned char* getContentsMut() override;

        void sendMessage(int sd) const override;
        virtual void sendMessage(int sd, const unsigned char* contents) const override;
        void receiveMessage(int sd) override;

        size_t getContentsSize() const override;
        size_t getReserved() const override;
        integrity getStatus() const override;

        buffer* getBuffer() override;

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
        void clearContents() override;

        const unsigned char* getContents() const override;
        unsigned char* getContentsMut() override;

        void sendMessage(int sd) const override;
        virtual void sendMessage(int sd, const unsigned char* contents) const override;
        void receiveMessage(int sd) override;

        size_t getContentsSize() const override;
        size_t getReserved() const override;
        integrity getStatus() const override;

        buffer* getBuffer() override;

        ~MessageDecorator() {
            delete wrapped_message;
        };
};

class AddAES256: public MessageDecorator {
    protected:
        unsigned char* key;
        unsigned char* iv;
    public:
        AddAES256(MessageInterface* message, unsigned char* key, unsigned char* iv);
        void decryptMessage();
        void sendMessage(int sd) const override;
        void receiveMessage(int sd) override;
};