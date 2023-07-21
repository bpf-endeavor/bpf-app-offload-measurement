#define _GNU_SOURCE

/* If a value should be shared across multiple message of a socket place it in
 * this struct */
struct client_ctx { };

#include "userspace/log.h"
#include "userspace/sock_app.h"
#include "userspace/util.h"

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
	int ret, len;
	char buf[BUFSIZE];

	/* Receive message and check the return value */
	RECV(client_fd, buf, BUFSIZE, 0);
	len = ret;

	/* Send a reply */
	ret = send(client_fd, buf, len, 0);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	struct socket_app app = {};

	/* parse args */
	if (argc < 4) {
		INFO("usage: prog <core> <ip> port\n");
		return 1;
	}
	app.core_listener = 0;
	app.core_worker = atoi(argv[1]);
	app.ip = argv[2];
	app.port = atoi(argv[3]);
	app.count_workers = 1;
	app.sock_handler = handle_client;
	app.on_sockready = NULL;
	app.on_sockclose = NULL;
	app.on_events = NULL;

	ret = run_server(&app);
	if (ret != 0) {
		ERROR("Failed to run server!\n");
		return 1;
	}

	return 0;
}
