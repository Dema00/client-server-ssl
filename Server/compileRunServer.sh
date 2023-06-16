rm server
g++ -Wall -ggdb3 main_server.cpp ./lib/server.cpp ../Message/message.cpp ../Shared/security.cpp ../Shared/database.cpp -o server -lpthread -lsqlite3 -lssl -lssl -lcrypto
./server 25565