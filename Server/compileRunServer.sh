rm server
g++ -Wall -ggdb3 main_server.cpp ./lib/server.cpp ../Message/message.cpp -o server -lcrypto -lpthread
./server 25565