#include "lib/header/server.h"

int main(int count, char *strings[])
{
	int portnum = 0;

	if ( count != 2 )
	{
		printf("Missing arguments in the execution, port number is required \n");
		exit(0);
	}

	portnum = atoi(strings[1]);

	if (portnum==0) {
		printf("Input port is not a valid number \n");
		exit(1);
	}

    Server server = Server(portnum, "bank.db");

    server.startServer();


    server.stopServer();
}