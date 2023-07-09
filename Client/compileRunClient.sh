rm client
g++ -Wall -ggdb3 main_client.cpp ./lib/client.cpp ../Message/message.cpp ../Shared/crypto.cpp ../Shared/database.cpp -o client -lcrypto -lpthread -lsqlite3
./client 127.0.0.1 25565