#include "lib/header/client.h"

int main(int args_count, char *args[]) {
	char *hostname, *portstr,*username;
	int portnum;

	if (args_count != 4) {
		printf("Missing arguments in the execution: ip, port number and username are required \n");
		exit(1);
	}

	hostname=args[1];
	portstr=args[2];
	username=args[3];
	portnum = atoi(portstr);

	if (portnum == 0) { //|| portnum == 80) {
		printf("Input port is not a valid number \n");
		exit(1);
	}

    Client client = Client(hostname, portnum, username, "clients.db");

    client.startClient();

    client.stopClient();
}