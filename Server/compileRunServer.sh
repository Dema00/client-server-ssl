rm server
g++ -Wall -ggdb3 main_server.cpp ./lib/server.cpp ../Message/message.cpp ../Shared/crypto.cpp ../Shared/database.cpp -o server -lpthread -lsqlite3 -lssl -lcrypto -DDEBUG
./server 25565