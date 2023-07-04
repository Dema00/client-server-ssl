#ifndef MESSAGE_H
#define MESSAGE_H
#endif

#ifdef DEBUG
#define DEBUG_MSG(exp) do { exp } while( false )
#include <sstream>
#else
#define DEBUG_MSG(str) do { } while ( false )
#endif

#include "../../Shared/header/crypto.h"

#include <ctime>

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

enum integrity {
    OK,
    WRONG_TIMESTAMP,
    WRONG_MAC,
    EMPTY,
    RECV_ERROR,
};

extern std::vector<std::string> MsgError;

typedef std::vector<unsigned char> buffer;


class MessageInterface {
    public:
        virtual void addContents(const unsigned char* new_contents, int len) = 0;
        virtual void addContentsBeginning(const unsigned char* new_contents, int len) = 0;
        virtual void clearContents() = 0;

        virtual const unsigned char* getContents() const = 0;
        virtual unsigned char* getContentsMut() = 0;

        virtual void sendMessage(int sd) = 0;
        virtual void sendMessage(int sd, const unsigned char* contents, int len) = 0;
        virtual void receiveMessage(int sd) = 0;

        virtual void finalizeReception() = 0;

        virtual size_t getContentsSize() const = 0;
        virtual size_t getReserved() const = 0;
        virtual integrity getStatus() const = 0;
        virtual void setStatus(integrity new_status) = 0;

        virtual buffer* getBuffer() = 0;

        virtual ~MessageInterface() {};
};

class Message: public MessageInterface {
    protected:
        buffer contents;
        integrity status;
    public:
        Message(std::size_t buf_size);

        void addContents(const unsigned char* new_contents, int len) override;
        void addContentsBeginning(const unsigned char* new_contents, int len) override;
        void clearContents() override;

        const unsigned char* getContents() const override;
        unsigned char* getContentsMut() override;

        void sendMessage(int sd) override;
        void sendMessage(int sd, const unsigned char* contents, int len) override;
        void receiveMessage(int sd) override;

        void finalizeReception() override;

        size_t getContentsSize() const override;
        size_t getReserved() const override;
        integrity getStatus() const override;
        void setStatus(integrity new_status) override;

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
        
        void addContents(const unsigned char* new_contents, int len) override;
        void addContentsBeginning(const unsigned char* new_contents, int len) override;
        void clearContents() override;

        const unsigned char* getContents() const override;
        unsigned char* getContentsMut() override;

        void sendMessage(int sd) override;
        void sendMessage(int sd, const unsigned char* contents, int len) override;
        void receiveMessage(int sd) override;

        void finalizeReception() override;

        size_t getContentsSize() const override;
        size_t getReserved() const override;
        integrity getStatus() const override;
        void setStatus(integrity new_status) override;

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
        void sendMessage(int sd) override;
        void receiveMessage(int sd) override;
        void finalizeReception() override;
};

class AddTimestamp: public MessageDecorator {
    public:
        AddTimestamp(MessageInterface* message);
        void sendMessage(int sd) override;
        void receiveMessage(int sd) override;
        void finalizeReception() override;
};

class AddMAC: public MessageDecorator {
    protected:
        unsigned char digest[256];
        unsigned char* key;
    public:
        AddMAC(MessageInterface* message, unsigned char* key);
        void sendMessage(int sd) override;
        void receiveMessage(int sd) override;
        void finalizeReception() override;
};

class AddRSA: public MessageDecorator {
    protected:
        EVP_PKEY* key;
    public:
        AddRSA(MessageInterface* message, unsigned char* raw_key);
        void sendMessage(int sd) override;
        void receiveMessage(int sd) override;
        void finalizeReception() override;
        void decryptMessage();

        ~AddRSA() {
            EVP_PKEY_free(key);
        }
};