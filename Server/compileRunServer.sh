rm server
g++ -Wall -ggdb3 main_server.cpp ./lib/server.cpp ../Message/message.cpp ../Shared/database.cpp -o server -lcrypto -lpthread -lsqlite3
./server 25565