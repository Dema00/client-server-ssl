#include "lib/header/client.h"

int main(int args_count, char *args[]) {
	char *hostname, *portstr;
	int portnum;

	if (args_count != 3) {
		printf("Missing arguments in the execution, both ip and port number are required \n");
		exit(1);
	}

	hostname=args[1];
	portstr=args[2];
	portnum = atoi(portstr);

	if (portnum == 0) { //|| portnum == 80) {
		printf("Input port is not a valid number \n");
		exit(1);
	}

    Client client = Client(hostname, portnum);

    client.startClient();

    client.stopClient();
}