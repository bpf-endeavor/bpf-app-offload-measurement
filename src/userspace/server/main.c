#define _GNU_SOURCE

/* If a value should be shared across multiple message of a socket place it in
 * this struct */
struct client_ctx { };

#include "userspace/log.h"
#include "userspace/sock_app.h"


/* Handle a socket message
 * Return value:
 *     0: Keep connection open for more data.
 *     1: Close the conneection.
 * */
int handle_client(int client_fd, struct client_ctx *ctx)
{
	int ret;
	char buf[BUFSIZE];
	ret = recv(client_fd, buf, BUFSIZE, 0);
	INFO("%s\n", buf);
	return 1;
}

int main(int argc, char *argv[])
{
	int ret;
	struct socket_app app;

	/* parse args */
	if (argc < 3) {
		INFO("usage: prog <core> <ip>\n");
		return 1;
	}
	app.core = atoi(argv[1]);
	app.port = 8080;
	app.ip = argv[2];
	app.count_workers = 1;
	app.sock_handler = handle_client;
	ret = run_server(&app);
	if (ret != 0) {
		ERROR("Failed to run server!\n");
		return 1;
	}

	return 0;
}
