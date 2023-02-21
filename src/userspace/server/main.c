#define _GNU_SOURCE

static int instructions;

/* If a value should be shared across multiple message of a socket place it in
 * this struct */
struct client_ctx { };

#include "userspace/log.h"
#include "userspace/sock_app.h"

#define RECV(fd, buf, size, flag)  {                  \
	ret = recv(fd, buf, size, flag);              \
	if (ret == 0)                                 \
		return 1;                             \
	if (ret < 0) {                                \
		if (errno != EWOULDBLOCK) {           \
			/* all message was received and connection is closed */ \
			return 1;                     \
		}                                     \
		return 0;                             \
	}                                             \
}


/* Handle a socket message
 * Return value:
 *     0: Keep connection open for more data.
 *     1: Close the conneection.
 * */
int handle_client(int client_fd, struct client_ctx *ctx)
{
	int ret, value;
	char buf[BUFSIZE];

	/* Receive message and check the return value */
	RECV(client_fd, buf, BUFSIZE, 0);
	value = *((int *)buf); /* read 4 bytes of message */
	for (int i = 0; i < instructions; i++) {
		value = value * 2;
	}
	*((int *)buf) = value;
	return 1;
}

int main(int argc, char *argv[])
{
	int ret;
	struct socket_app app;

	/* parse args */
	if (argc < 4) {
		INFO("usage: prog <core> <ip> <num insts>\n");
		return 1;
	}
	app.core = atoi(argv[1]);
	app.port = 8080;
	app.ip = argv[2];
	app.count_workers = 1;
	app.sock_handler = handle_client;

	/* How many instructions to spend per packet */
	instructions = atoi(argv[3]);

	ret = run_server(&app);
	if (ret != 0) {
		ERROR("Failed to run server!\n");
		return 1;
	}

	return 0;
}
