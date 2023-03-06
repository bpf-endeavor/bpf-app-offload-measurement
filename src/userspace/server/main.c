#define _GNU_SOURCE

static int instructions;

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


/* static double last_ts; */
/* static long long int sent; */


/* Handle a socket message
 * Return value:
 *     0: Keep connection open for more data.
 *     1: Close the conneection.
 * */
int handle_client(int client_fd, struct client_ctx *ctx)
{
	int ret, len, value, i;
	char buf[BUFSIZE];
	/* double now; */
	/* double diff; */

	/* Receive message and check the return value */
	RECV(client_fd, buf, BUFSIZE, 0);
	len = ret;

	/* INFO("%s\n", buf); */
	value = *((int *)buf); /* read 4 bytes of message */
	for (i = 0; i < instructions; i++) {
		value += ((unsigned char *)buf)[i % len];
	}
	*((int *)buf) = value;

	/* Report throughput */
	/* sent++; */
	/* now = get_time(); */
	/* diff = now - last_ts; */
	/* if (diff > 2) { */
	/* 	printf("i = %d, %d\n", i, value); */
	/* 	printf("Throughput: %d\n", (int)(sent / diff)); */
	/* 	last_ts = now; */
	/* 	sent = 0; */
	/* } */

	/* Send a reply */
	ret = send(client_fd, buf, len, 0);

	return 0;
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
