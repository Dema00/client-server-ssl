rm client
g++ -Wall -ggdb3 main_client.cpp ./lib/client.cpp ../Message/message.cpp ../Shared/security.cpp -o client -lcrypto -lpthread
./client 127.0.0.1 25565